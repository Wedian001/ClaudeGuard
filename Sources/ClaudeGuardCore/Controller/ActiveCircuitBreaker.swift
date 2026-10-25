import Foundation
import AppKit
import Network
import SystemConfiguration
import Darwin

public protocol SignalControlling: Sendable {
    func sendSignal(_ sig: Int32, to pid: Int32) -> Bool
}

public struct POSIXSignalController: SignalControlling {
    public init() {}

    public func sendSignal(_ sig: Int32, to pid: Int32) -> Bool {
        guard pid > 1, pid != ProcessInfo.processInfo.processIdentifier else { return false }
        return Darwin.kill(pid, sig) == 0
    }
}

public struct CircuitBreakerFreezeEvent: Sendable, Equatable {
    public var timestamp: Date
    public var reason: String
    public var frozenProcesses: [ClaudeProcessInfo]

    public init(timestamp: Date = Date(), reason: String, frozenProcesses: [ClaudeProcessInfo]) {
        self.timestamp = timestamp
        self.reason = reason
        self.frozenProcesses = frozenProcesses
    }
}

/// Monitors system network changes (SCDynamicStore + NWPathMonitor) and app launches (NSWorkspace)
/// in real time. Immediately suspends (SIGSTOP) Claude processes if proxy/TUN drops while Claude runs
/// or if Claude is launched directly from Dock/Spotlight while exit is unsafe.
public final class ActiveCircuitBreaker: @unchecked Sendable {
    private let netEnv: any NetworkEnvironmentInspecting
    private let procEnv: any ProcessAndEnvironmentInspecting
    private let prober: any NetworkProbing
    private let signaler: any SignalControlling

    private let monitorQueue = DispatchQueue(label: "com.claudeguard.circuitbreaker", qos: .userInteractive)
    private var pathMonitor: NWPathMonitor?
    private var dynamicStore: SCDynamicStore?
    private var workspaceObservers: [NSObjectProtocol] = []
    private var heartbeatTask: Task<Void, Never>?

    private let lock = NSLock()
    private var _isEnabled: Bool = true
    private var _isPerformingIntentionalLaunch: Bool = false
    private var _lastKnownSafeExit: Bool = false
    private var _frozenPIDs: Set<Int32> = []
    private var _debouncePending: Bool = false

    public var onFreezeTriggered: (@Sendable (CircuitBreakerFreezeEvent) -> Void)?
    public var onEnvironmentChanged: (@Sendable () -> Void)?

    public init(
        netEnv: any NetworkEnvironmentInspecting = SystemProxyAndRouteInspector(),
        procEnv: any ProcessAndEnvironmentInspecting = ProcessAndSocketScanner(),
        prober: any NetworkProbing = LiveNetworkProbeService(),
        signaler: any SignalControlling = POSIXSignalController()
    ) {
        self.netEnv = netEnv
        self.procEnv = procEnv
        self.prober = prober
        self.signaler = signaler
    }

    public var isEnabled: Bool {
        get { lock.withLock { _isEnabled } }
        set { lock.withLock { _isEnabled = newValue } }
    }

    public func setIntentionalLaunchWindow(_ active: Bool) {
        lock.withLock { _isPerformingIntentionalLaunch = active }
    }

    public func updateLastKnownSafeExit(_ safe: Bool) {
        lock.withLock { _lastKnownSafeExit = safe }
    }

    public var frozenPIDs: Set<Int32> {
        lock.withLock { _frozenPIDs }
    }

    public func startMonitoring() {
        stopMonitoring()

        // 1. NWPathMonitor for instant interface / route topology transitions
        let nwMonitor = NWPathMonitor()
        nwMonitor.pathUpdateHandler = { [weak self] _ in
            self?.handleNetworkTopologyChange(source: "NWPathMonitor")
        }
        nwMonitor.start(queue: monitorQueue)
        self.pathMonitor = nwMonitor

        // 2. SCDynamicStore for sub-10ms system proxy & IPv4/IPv6 state changes
        var context = SCDynamicStoreContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        let callback: SCDynamicStoreCallBack = { _, _, info in
            guard let info else { return }
            let instance = Unmanaged<ActiveCircuitBreaker>.fromOpaque(info).takeUnretainedValue()
            instance.handleNetworkTopologyChange(source: "SCDynamicStore")
        }
        if let store = SCDynamicStoreCreate(nil, "com.claudeguard.netwatcher" as CFString, callback, &context) {
            let keys: [CFString] = [
                "State:/Network/Global/Proxies" as CFString,
                "State:/Network/Global/IPv4" as CFString,
                "State:/Network/Global/IPv6" as CFString
            ]
            SCDynamicStoreSetNotificationKeys(store, keys as CFArray, nil)
            SCDynamicStoreSetDispatchQueue(store, monitorQueue)
            self.dynamicStore = store
        }

        // 3. NSWorkspace notifications for catching accidental direct Dock/Spotlight launch of Claude.app
        let nc = NSWorkspace.shared.notificationCenter
        let launchObs = nc.addObserver(
            forName: NSWorkspace.didLaunchApplicationNotification,
            object: nil,
            queue: nil
        ) { [weak self] note in
            guard let self else { return }
            if let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
               app.bundleIdentifier == "com.anthropic.claudefordesktop" {
                self.handleClaudeLaunchedExternally()
            } else {
                self.onEnvironmentChanged?()
            }
        }

        let termObs = nc.addObserver(
            forName: NSWorkspace.didTerminateApplicationNotification,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            self?.onEnvironmentChanged?()
        }
        self.workspaceObservers = [launchObs, termObs]

        // 4. Lightweight 15s canary heartbeat ONLY while Claude processes are active (catches "Fake TUN online" dead nodes)
        self.heartbeatTask = Task.detached(priority: .utility) { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(15))
                guard let self, self.isEnabled else { continue }
                await self.performActiveHeartbeatCheck()
            }
        }
    }

    public func stopMonitoring() {
        pathMonitor?.cancel()
        pathMonitor = nil
        if let store = dynamicStore {
            SCDynamicStoreSetDispatchQueue(store, nil)
            dynamicStore = nil
        }
        let nc = NSWorkspace.shared.notificationCenter
        for obs in workspaceObservers {
            nc.removeObserver(obs)
        }
        workspaceObservers.removeAll()
        heartbeatTask?.cancel()
        heartbeatTask = nil
    }

    private func handleClaudeLaunchedExternally() {
        let shouldCheck = lock.withLock { _isEnabled && !_isPerformingIntentionalLaunch }
        onEnvironmentChanged?()
        guard shouldCheck else { return }

        monitorQueue.async { [weak self] in
            guard let self else { return }
            let proxy = self.netEnv.inspectProxySettings()
            let routes = self.netEnv.inspectKernelRoutes()
            let mode = self.netEnv.classifyTransportMode(proxy: proxy, routes: routes)

            if !mode.isProtectedLocally {
                _ = self.freezeAllClaudeProcesses(reason: "检测到从未开代理/TUN 环境下直接启动了 Claude Desktop，已立即挂起进程防止直连发包！")
            } else {
                // Verify via fast harmless canary in case TUN is stale or pointing to CN
                Task {
                    let canary = await self.prober.probeTrace(label: "LaunchGuard", urlString: "https://1.1.1.1/cdn-cgi/trace", timeout: 3.0)
                    if let restricted = canary.restrictedRegionName {
                        _ = self.freezeAllClaudeProcesses(reason: "拦截到 Claude 启动时当前出口位于\(restricted)（\(canary.ip ?? "")），已紧急冻结进程保护账号！")
                    } else if canary.succeeded {
                        self.updateLastKnownSafeExit(true)
                    }
                }
            }
        }
    }

    private func handleNetworkTopologyChange(source: String) {
        let shouldRun = lock.withLock { () -> Bool in
            guard _isEnabled else { return false }
            if _debouncePending { return false }
            _debouncePending = true
            return true
        }
        guard shouldRun else { return }

        monitorQueue.asyncAfter(deadline: .now() + .milliseconds(80)) { [weak self] in
            guard let self else { return }
            self.lock.withLock { self._debouncePending = false }
            self.evaluateInstantBreach(triggerSource: source)
            self.onEnvironmentChanged?()
        }
    }

    public func evaluateInstantBreach(triggerSource: String) {
        guard isEnabled else { return }
        let procs = procEnv.scanClaudeProcesses()
        let activeRunning = procs.filter { !$0.isStopped }
        guard !activeRunning.isEmpty else { return }

        let proxy = netEnv.inspectProxySettings()
        let routes = netEnv.inspectKernelRoutes()
        let mode = netEnv.classifyTransportMode(proxy: proxy, routes: routes)

        if !mode.isProtectedLocally {
            _ = freezeAllClaudeProcesses(
                processes: procs,
                reason: "Claude 运行期间检测到代理或 TUN 已断开（触发源：\(triggerSource)），已毫秒级冻结全部进程阻断直连遥测！"
            )
            return
        }

        if routes.hasIPv6DirectLeakRisk {
            // Double check if IPv6 actually leaks to restricted region
            Task {
                let v6 = await self.prober.probeTrace(label: "IPv6Guard", urlString: "https://[2606:4700:4700::1111]/cdn-cgi/trace", timeout: 2.0)
                if v6.succeeded, let rName = v6.restrictedRegionName {
                    _ = self.freezeAllClaudeProcesses(reason: "网络切换后检测到原生 IPv6 直连暴露至\(rName)，已紧急冻结 Claude！")
                }
            }
        }
    }

    private func performActiveHeartbeatCheck() async {
        let procs = procEnv.scanClaudeProcesses()
        let running = procs.filter { !$0.isStopped }
        guard !running.isEmpty else { return }

        let canary = await prober.probeTrace(label: "Heartbeat", urlString: "https://1.1.1.1/cdn-cgi/trace", timeout: 3.5)
        if canary.succeeded, let restricted = canary.restrictedRegionName {
            _ = freezeAllClaudeProcesses(
                processes: procs,
                reason: "后台心跳发现代理出口已掉回\(restricted)（\(canary.ip ?? "")），已紧急冻结 Claude 阻止带凭据请求暴露！"
            )
        }
    }

    // MARK: - Freeze (SIGSTOP), Resume (SIGCONT), Zero-Telemetry Force Kill (SIGKILL)

    @discardableResult
    public func freezeAllClaudeProcesses(
        processes: [ClaudeProcessInfo]? = nil,
        reason: String
    ) -> CircuitBreakerFreezeEvent? {
        let targets = processes ?? procEnv.scanClaudeProcesses()
        guard !targets.isEmpty else { return nil }

        // Suspend main & helper processes immediately via SIGSTOP
        var frozenList: [ClaudeProcessInfo] = []
        for proc in targets {
            if signaler.sendSignal(SIGSTOP, to: proc.pid) || proc.isStopped {
                var updated = proc
                updated.stateCode = "T"
                frozenList.append(updated)
            }
        }

        guard !frozenList.isEmpty else { return nil }
        lock.withLock {
            for p in frozenList { _frozenPIDs.insert(p.pid) }
            _lastKnownSafeExit = false
        }

        let event = CircuitBreakerFreezeEvent(reason: reason, frozenProcesses: frozenList)
        onFreezeTriggered?(event)
        return event
    }

    /// Resumes frozen Claude processes via SIGCONT (must ONLY be called after Open Gate passes!)
    public func resumeFrozenProcesses() -> Int {
        let procs = procEnv.scanClaudeProcesses()
        let pidsToResume = lock.withLock { _frozenPIDs }.union(procs.filter(\.isStopped).map(\.pid))
        var count = 0
        for pid in pidsToResume {
            if signaler.sendSignal(SIGCONT, to: pid) {
                count += 1
            }
        }
        lock.withLock {
            _frozenPIDs.removeAll()
            _lastKnownSafeExit = true
        }
        return count
    }

    /// Terminates frozen or unsafe Claude processes directly in kernel via SIGKILL
    /// so Electron's user-space `beforeQuit` telemetry hook NEVER executes over an unsafe connection.
    public func forceKillWithoutTelemetry() -> Int {
        let procs = procEnv.scanClaudeProcesses()
        let allPIDs = lock.withLock { _frozenPIDs }.union(procs.map(\.pid))
        var killed = 0
        // First ensure SIGSTOP so nothing races during loop, then SIGKILL
        for pid in allPIDs {
            _ = signaler.sendSignal(SIGSTOP, to: pid)
        }
        for pid in allPIDs {
            if signaler.sendSignal(SIGKILL, to: pid) {
                killed += 1
            }
        }
        lock.withLock { _frozenPIDs.removeAll() }
        return killed
    }
}
