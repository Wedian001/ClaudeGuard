import Foundation
import AppKit
import UserNotifications
import ServiceManagement

@MainActor
@Observable
public final class ClaudeLifecycleController {
    public enum WorkflowStage: Sendable, Equatable {
        case idle
        case checkingOpenGate(step: String)
        case launchingClaude
        case guardingActiveClaude
        case quittingDraining(step: String, remainingCount: Int, elapsedSeconds: Int)
        case safeToTurnOffProxy(confirmedAt: Date)
        case blockedCannotOpen(reason: String)
        case emergencyFrozen(reason: String, frozenCount: Int)
    }

    public private(set) var stage: WorkflowStage = .idle
    public private(set) var openReport: OpenGateReport?
    public private(set) var closeReport: CloseGateReport?
    public private(set) var ipHistory: [IPHistoryEntry] = []
    public private(set) var lastFreezeEvent: CircuitBreakerFreezeEvent?

    public var isBusy: Bool {
        switch stage {
        case .checkingOpenGate, .launchingClaude, .quittingDraining:
            return true
        default:
            return false
        }
    }

    public var maskIPInUI: Bool = false
    public var selectedDashboardTab: Int = 0
    public var allowOpenWithWarnings: Bool = true
    public var activeProtectionEnabled: Bool = true {
        didSet {
            circuitBreaker.isEnabled = activeProtectionEnabled
        }
    }

    public let evaluator: GateEvaluator
    public let circuitBreaker: ActiveCircuitBreaker
    private let signaler: any SignalControlling

    public var onEmergencyFreezeAlert: ((CircuitBreakerFreezeEvent) -> Void)?
    public var onSafeToCloseProxyConfirmed: (() -> Void)?

    public init(
        evaluator: GateEvaluator = GateEvaluator(),
        circuitBreaker: ActiveCircuitBreaker? = nil,
        signaler: any SignalControlling = POSIXSignalController()
    ) {
        self.evaluator = evaluator
        self.signaler = signaler
        self.circuitBreaker = circuitBreaker ?? ActiveCircuitBreaker(
            netEnv: evaluator.netEnv,
            procEnv: evaluator.procEnv,
            prober: evaluator.prober,
            signaler: signaler
        )
        self.ipHistory = evaluator.historyStore.load()
        wireCallbacks()
    }

    private func wireCallbacks() {
        circuitBreaker.onFreezeTriggered = { [weak self] event in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.lastFreezeEvent = event
                self.stage = .emergencyFrozen(reason: event.reason, frozenCount: event.frozenProcesses.count)
                self.refreshLocalCloseGate()
                NSSound(named: "Basso")?.play()
                self.postSystemNotification(
                    title: "❄️ Claude 已被紧急冻结保护",
                    body: event.reason
                )
                self.onEmergencyFreezeAlert?(event)
            }
        }

        circuitBreaker.onEnvironmentChanged = { [weak self] in
            Task { @MainActor [weak self] in
                guard let self, !self.isBusy else { return }
                self.refreshFastLocalState()
            }
        }
    }

    public func startServices() {
        requestNotificationPermissionIfBundled()
        circuitBreaker.startMonitoring()
        refreshFastLocalState()
        Task {
            await runOpenCheck(deep: false)
        }
    }

    // MARK: - Fast Local Refresh

    public func refreshFastLocalState() {
        let closeRep = evaluator.evaluateCloseGate()
        self.closeReport = closeRep
        self.ipHistory = evaluator.historyStore.load()

        if let frozenProcs = closeRep.processes.isEmpty ? nil : closeRep.processes.filter(\.isStopped),
           !frozenProcs.isEmpty {
            let reason = lastFreezeEvent?.reason ?? "检测到已挂起的 Claude 进程"
            stage = .emergencyFrozen(reason: reason, frozenCount: frozenProcs.count)
            return
        }

        if !closeRep.processes.isEmpty {
            if case .quittingDraining = stage { return }
            stage = .guardingActiveClaude
        } else if case .guardingActiveClaude = stage {
            // Claude exited on its own — run a quick drain confirmation
            if closeRep.isSafeToCloseProxy {
                stage = .safeToTurnOffProxy(confirmedAt: Date())
            } else {
                stage = .idle
            }
        }
    }

    public func refreshLocalCloseGate() {
        self.closeReport = evaluator.evaluateCloseGate()
    }

    // MARK: - Open Check & Deep Diagnostic

    @discardableResult
    public func runOpenCheck(deep: Bool = false, sampleCount: Int? = nil) async -> OpenGateReport {
        let samples = sampleCount ?? (deep ? 8 : 6)
        stage = .checkingOpenGate(step: "准备检测本地路由与双栈网络出口...")
        let evaluatorCopy = evaluator

        let report = await Task.detached(priority: .userInitiated) {
            await evaluatorCopy.evaluateOpenGate(
                includeNetwork: true,
                deep: deep,
                sampleCount: samples,
                timeout: deep ? 6.0 : 5.0
            ) { stepMsg in
                Task { @MainActor in
                    if case .checkingOpenGate = self.stage {
                        self.stage = .checkingOpenGate(step: stepMsg)
                    }
                }
            }
        }.value

        self.openReport = report
        self.ipHistory = evaluator.historyStore.load()
        let closeRep = evaluator.evaluateCloseGate()
        self.closeReport = closeRep

        let isSafe = (report.verdict == .go || report.verdict == .goWithWarnings)
        circuitBreaker.updateLastKnownSafeExit(isSafe)

        if !closeRep.processes.filter(\.isStopped).isEmpty {
            stage = .emergencyFrozen(
                reason: lastFreezeEvent?.reason ?? "存在已冻结的 Claude 进程",
                frozenCount: closeRep.processes.filter(\.isStopped).count
            )
        } else if !closeRep.processes.isEmpty {
            stage = .guardingActiveClaude
        } else if !isSafe {
            stage = .blockedCannotOpen(reason: report.summaryHeadline)
        } else {
            stage = .idle
        }
        return report
    }

    // MARK: - Closed Loop 1: Safe Check -> Open Claude Desktop

    @discardableResult
    public func checkAndOpenClaude() async -> Bool {
        let report = await runOpenCheck(deep: false, sampleCount: 6)

        guard report.claudeInstalled else {
            stage = .blockedCannotOpen(reason: "未找到 /Applications/Claude.app，请先安装 Claude Desktop。")
            NSSound(named: "Basso")?.play()
            return false
        }

        let permitted: Bool
        switch report.verdict {
        case .go:
            permitted = true
        case .goWithWarnings:
            permitted = allowOpenWithWarnings
        case .noGo, .frozenEmergency:
            permitted = false
        }

        guard permitted else {
            stage = .blockedCannotOpen(reason: report.summaryHeadline)
            NSSound(named: "Basso")?.play()
            return false
        }

        stage = .launchingClaude
        circuitBreaker.setIntentionalLaunchWindow(true)
        defer {
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(3))
                self.circuitBreaker.setIntentionalLaunchWindow(false)
            }
        }

        let appURL = URL(fileURLWithPath: "/Applications/Claude.app")
        let config = NSWorkspace.OpenConfiguration()
        config.activates = true

        do {
            _ = try await NSWorkspace.shared.openApplication(at: appURL, configuration: config)
            try? await Task.sleep(for: .milliseconds(600))
            self.closeReport = evaluator.evaluateCloseGate()
            stage = .guardingActiveClaude
            postSystemNotification(
                title: "🟢 Claude 已安全启动",
                body: "出口 \(report.claudeTrace?.loc ?? "") (\(report.claudeTrace?.ip ?? "")) 校验通过，实时断路器守护中（使用期间请勿关闭代理）。"
            )
            return true
        } catch {
            stage = .blockedCannotOpen(reason: "启动 Claude.app 失败：\(error.localizedDescription)")
            return false
        }
    }

    // MARK: - Closed Loop 2: Safe Quit Claude -> Drain Verification -> Prompt Safe to Close Proxy

    @discardableResult
    public func safeQuitClaudeAndVerifyDrain(maxWaitSeconds: Int = 30) async -> CloseGateReport {
        let initialClose = evaluator.evaluateCloseGate()
        self.closeReport = initialClose

        if initialClose.isSafeToCloseProxy {
            stage = .safeToTurnOffProxy(confirmedAt: Date())
            NSSound(named: "Glass")?.play()
            postSystemNotification(
                title: "✅ 现在可以安全关闭代理",
                body: "没有任何运行中的 Claude 进程或活动网络连接。"
            )
            onSafeToCloseProxyConfirmed?()
            return initialClose
        }

        // CRITICAL SAFETY CHECK: If proxy/TUN is ALREADY disconnected, NEVER run graceful quit
        // because Electron's `beforeQuit` would flush Bearer telemetry over CN direct!
        let proxy = evaluator.netEnv.inspectProxySettings()
        let routes = evaluator.netEnv.inspectKernelRoutes()
        let mode = evaluator.netEnv.classifyTransportMode(proxy: proxy, routes: routes)
        if !mode.isProtectedLocally || !initialClose.processes.filter(\.isStopped).isEmpty {
            _ = circuitBreaker.forceKillWithoutTelemetry()
            try? await Task.sleep(for: .milliseconds(500))
            return await waitUntilDrained(maxWaitSeconds: 8)
        }

        // Graceful quit of Claude Desktop via NSRunningApplication
        stage = .quittingDraining(
            step: "正在向 Claude Desktop 发送安全退出指令...",
            remainingCount: initialClose.processes.count,
            elapsedSeconds: 0
        )

        let runningDesktopApps = NSWorkspace.shared.runningApplications.filter {
            $0.bundleIdentifier == "com.anthropic.claudefordesktop"
        }
        for app in runningDesktopApps {
            _ = app.terminate()
        }

        // Also send SIGTERM to desktopMain if NSRunningApplication didn't catch it
        for proc in initialClose.processes where proc.kind == .desktopMain {
            _ = signaler.sendSignal(SIGTERM, to: proc.pid)
        }

        return await waitUntilDrained(maxWaitSeconds: maxWaitSeconds)
    }

    private func waitUntilDrained(maxWaitSeconds: Int) async -> CloseGateReport {
        let evaluatorCopy = evaluator
        let totalTicks = max(4, maxWaitSeconds * 4) // 250ms per tick

        for tick in 0..<totalTicks {
            let elapsed = tick / 4
            let current = await Task.detached(priority: .userInitiated) {
                evaluatorCopy.evaluateCloseGate()
            }.value
            self.closeReport = current

            if current.isSafeToCloseProxy {
                stage = .safeToTurnOffProxy(confirmedAt: Date())
                NSSound(named: "Glass")?.play()
                postSystemNotification(
                    title: "✅ Claude 已完全退出，现在可以安全关闭代理！",
                    body: "全部主进程、辅助进程、更新器与网络连接均已排空并完成静默核验。"
                )
                onSafeToCloseProxyConfirmed?()
                return current
            }

            // Build human-readable draining status message
            let stepMsg: String
            let cliProcs = current.processes.filter { $0.kind == .claudeCodeCLI }
            if !cliProcs.isEmpty && current.processes.count == cliProcs.count {
                stepMsg = "Claude Desktop 已退出，但检测到终端仍有 \(cliProcs.count) 个 Claude Code CLI 会话运行中（PID \(cliProcs.map { String($0.pid) }.joined(separator: ", "))），请先退出终端会话..."
            } else if !current.processes.isEmpty {
                let kinds = Array(Set(current.processes.map(\.kind.rawValue))).joined(separator: "、")
                stepMsg = "等待进程退出排空中：\(kinds)..."
            } else if !current.claudeSockets.isEmpty {
                stepMsg = "进程已退出，正在等待 \(current.claudeSockets.count) 条内核网络连接排空..."
            } else {
                stepMsg = "正在确认 main.log 退出清理静默（满 2 秒）..."
            }

            stage = .quittingDraining(
                step: stepMsg,
                remainingCount: current.processes.count + current.claudeSockets.count,
                elapsedSeconds: elapsed
            )

            try? await Task.sleep(for: .milliseconds(250))
        }

        let finalReport = evaluator.evaluateCloseGate()
        self.closeReport = finalReport
        if finalReport.isSafeToCloseProxy {
            stage = .safeToTurnOffProxy(confirmedAt: Date())
            NSSound(named: "Glass")?.play()
            onSafeToCloseProxyConfirmed?()
        } else {
            stage = .guardingActiveClaude
            NSSound(named: "Basso")?.play()
        }
        return finalReport
    }

    // MARK: - Emergency Freeze Recovery Actions

    public func verifyProxyAndResumeFrozenClaude() async -> Bool {
        stage = .checkingOpenGate(step: "正在验证恢复后的代理出口是否安全...")
        let evaluatorCopy = evaluator
        let report = await Task.detached(priority: .userInitiated) {
            await evaluatorCopy.evaluateOpenGate(includeNetwork: true, deep: false, sampleCount: 3, timeout: 4.5)
        }.value
        self.openReport = report

        guard report.verdict == .go || (report.verdict == .goWithWarnings && allowOpenWithWarnings) else {
            let frozenCnt = closeReport?.processes.filter(\.isStopped).count ?? 1
            stage = .emergencyFrozen(
                reason: "出口仍不安全（\(report.summaryHeadline)），继续保持冻结保护！请先修复代理节点。",
                frozenCount: frozenCnt
            )
            NSSound(named: "Basso")?.play()
            return false
        }

        _ = circuitBreaker.resumeFrozenProcesses()
        lastFreezeEvent = nil
        try? await Task.sleep(for: .milliseconds(300))
        self.closeReport = evaluator.evaluateCloseGate()
        stage = .guardingActiveClaude
        NSSound(named: "Glass")?.play()
        postSystemNotification(
            title: "🟢 代理已恢复，Claude 已无损解冻继续运行",
            body: "当前出口：\(report.claudeTrace?.loc ?? "") (\(report.claudeTrace?.ip ?? ""))"
        )
        return true
    }

    public func emergencyForceCloseFrozenClaude() async {
        _ = circuitBreaker.forceKillWithoutTelemetry()
        lastFreezeEvent = nil
        _ = await waitUntilDrained(maxWaitSeconds: 8)
    }

    // MARK: - Utilities (Launch Proxy Client, IP History, Login Item, Notifications)

    public func openProxyClient(_ client: ProxyClientApp) {
        let url = URL(fileURLWithPath: client.path)
        let config = NSWorkspace.OpenConfiguration()
        config.activates = true
        NSWorkspace.shared.openApplication(at: url, configuration: config, completionHandler: nil)
    }

    public func clearIPHistory() {
        evaluator.historyStore.clear()
        ipHistory = []
    }

    public var isLaunchAtLoginEnabled: Bool {
        guard Bundle.main.bundleURL.pathExtension == "app" else { return false }
        return SMAppService.mainApp.status == .enabled
    }

    public func setLaunchAtLogin(_ enabled: Bool) throws {
        guard Bundle.main.bundleURL.pathExtension == "app" else { return }
        if enabled {
            try SMAppService.mainApp.register()
        } else {
            try SMAppService.mainApp.unregister()
        }
    }

    private var canUseUserNotifications: Bool {
        Bundle.main.bundleIdentifier != nil && Bundle.main.bundleURL.pathExtension == "app"
    }

    private func requestNotificationPermissionIfBundled() {
        guard canUseUserNotifications else { return }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }

    private func postSystemNotification(title: String, body: String) {
        guard canUseUserNotifications else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req, withCompletionHandler: nil)
    }
}
