import Foundation
import Testing
@testable import ClaudeGuardCore

@Suite("ClaudeGuard Core Security & Gate Tests")
struct ClaudeGuardTests {

    @Test("L3/L4: Detects system proxy bypass of hyphenated Datadog telemetry domain")
    func testProxyBypassDetection() {
        let scutilOut = """
        <dictionary> {
          ExceptionsList : <array> {
            0 : 127.0.0.1
            1 : *.local
            2 : browser-intake-us5-datadoghq.com
          }
          HTTPEnable : 1
          HTTPPort : 7890
          HTTPProxy : 127.0.0.1
          HTTPSEnable : 1
          HTTPSPort : 7890
          HTTPSProxy : 127.0.0.1
        }
        """
        let snap = SystemProxyAndRouteInspector.parseScutilProxyOutput(scutilOut)
        #expect(snap.httpEnabled == true)
        #expect(snap.httpsPort == 7890)
        #expect(snap.domainRoutingConsistent == false)
        #expect(snap.bypassedCriticalDomains.contains("browser-intake-us5-datadoghq.com"))
    }

    @Test("L2/L5: Recognizes Mihomo split-prefix TUN route and flags physical IPv6 leak route")
    func testMihomoSplitRouteAndIPv6Leak() {
        let defaultOut = "   route to: default\n  interface: en0\n"
        let anthropicV4Out = "   route to: 160.79.104.1\n  interface: utun8\n"
        let anthropicV6Out = "   route to: 2607:6bc0::1\n  interface: en0\n"
        let ifconfigOut = """
        lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
        \tinet6 ::1 prefixlen 128
        en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        \tinet6 fe80::aede:48ff:fe00:1122%en0 prefixlen 64 scopeid 0x6
        \tinet6 3fff::88 prefixlen 64 autoconf secured
        utun8: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 9000
        \tinet 198.18.0.1 --> 198.18.0.2 netmask 0xfffffffc
        """

        let rDef = SystemProxyAndRouteInspector.parseRouteGetOutput(defaultOut, target: "default")
        let rV4 = SystemProxyAndRouteInspector.parseRouteGetOutput(anthropicV4Out, target: "160.79.104.1")
        let rV6 = SystemProxyAndRouteInspector.parseRouteGetOutput(anthropicV6Out, target: "2607:6bc0::1")
        let pubV6 = SystemProxyAndRouteInspector.parsePhysicalPublicIPv6(from: ifconfigOut)

        let snap = KernelRouteSnapshot(
            defaultIPv4: rDef,
            cloudflareIPv4: rV4,
            anthropicIPv4: rV4,
            anthropicIPv6: rV6,
            publicIPv6AddressesOnPhysical: pubV6
        )

        #expect(rDef.isTunInterface == false)
        #expect(snap.isTunActiveForClaude == true)
        #expect(pubV6 == ["3fff::88"])
        #expect(snap.hasIPv6DirectLeakRisk == true)
    }

    @Test("L1: Classifies all 8 Claude family process kinds and excludes ClaudeGuard itself")
    func testProcessFamilyClassification() {
        let psText = """
          501     1 Ss   /Applications/Claude.app/Contents/MacOS/Claude
          502   501 S    /Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer).app/Contents/MacOS/Claude Helper (Renderer)
          503     1 S    /Applications/Claude.app/Contents/Frameworks/Squirrel.framework/Versions/A/Resources/ShipIt com.anthropic.claudefordesktop.ShipIt
          504   411 S    /Applications/Claude.app/Contents/Helpers/chrome-native-host chrome-extension://fcoeoabgfenejglbffodgkkbkcdhcgfn/
          505   501 S    /Applications/Claude.app/Contents/Helpers/app-cu-helper
          506   501 S    /Applications/Claude.app/Contents/Frameworks/Electron Framework.framework/Helpers/chrome_crashpad_handler --database=/Users/test/Library/Application Support/Claude/Crashpad
          507   800 T+   /opt/homebrew/Caskroom/claude-code/2.1.139/claude
          508   501 S    /Applications/Claude.app/Contents/Helpers/claude-ssh-askpass
          990     1 S    /Applications/ClaudeGuard.app/Contents/MacOS/ClaudeGuardApp
          991   800 S    /usr/local/bin/claude-guard status
        """

        let list = ProcessAndSocketScanner.parsePSOutput(psText, excludingPID: -1)
        #expect(list.count == 8)
        let kinds = Set(list.map(\.kind))
        #expect(kinds.count == 8)

        let cliProc = list.first(where: { $0.kind == .claudeCodeCLI })
        #expect(cliProc?.isStopped == true)
    }

    @Test("L1/L6: Parses lsof sockets separating Claude sockets from browser Anthropic connections")
    func testLsofSocketParsing() {
        let lsofText = """
        COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
        Claude      502 testuser   28u  IPv4 0x1234567890      0t0  TCP 198.18.0.1:54321->160.79.104.25:443 (ESTABLISHED)
        Google      812 testuser   41u  IPv4 0x1234567891      0t0  TCP 198.18.0.1:54399->160.79.105.10:443 (ESTABLISHED)
        """
        let (claudeSocks, browserSocks) = ProcessAndSocketScanner.parseLsofSockets(lsofText, claudePIDs: [501, 502])
        #expect(claudeSocks.count == 1)
        #expect(claudeSocks.first?.isAnthropicIPRange == true)
        #expect(browserSocks.count == 1)
        #expect(browserSocks.first?.processName == "Google")
    }

    @Test("L4: Encodes and decodes RFC 5389 STUN XOR-MAPPED-ADDRESS for IPv4 and IPv6")
    func testSTUNCodecIPv4AndIPv6() {
        let txID: [UInt8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0]
        let req = STUNProbe.buildBindingRequest(transactionID: txID)
        #expect(req.count == 20)

        // IPv4: 203.0.113.11
        let v4Xor: [UInt8] = [203 ^ 0x21, 0 ^ 0x12, 113 ^ 0xA4, 11 ^ 0x42]
        var respV4 = Data([0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42])
        respV4.append(contentsOf: txID)
        respV4.append(contentsOf: [0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00])
        respV4.append(contentsOf: v4Xor)
        #expect(STUNProbe.parseBindingResponse(respV4, transactionID: txID) == "203.0.113.11")

        // IPv6: 2607:6bc0:0:0:0:0:0:1
        let rawV6: [UInt8] = [0x26, 0x07, 0x6b, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        let mask: [UInt8] = [0x21, 0x12, 0xA4, 0x42] + txID
        let xorV6 = (0..<16).map { rawV6[$0] ^ mask[$0] }
        var respV6 = Data([0x01, 0x01, 0x00, 0x18, 0x21, 0x12, 0xA4, 0x42])
        respV6.append(contentsOf: txID)
        respV6.append(contentsOf: [0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00])
        respV6.append(contentsOf: xorV6)
        #expect(STUNProbe.parseBindingResponse(respV6, transactionID: txID) == "2607:6bc0:0:0:0:0:0:1")
    }

    @Test("L2/Fail-Closed: Blocks immediately when IPv4 is US but IPv6 canary leaks CN without touching claude.ai")
    func testIPv6CanaryLeakBlocksBeforeClaudeProbe() async {
        let prober = ConfigurableMockProber(
            v4Result: TraceProbeResult(label: "v4", url: "https://1.1.1.1/cdn-cgi/trace", ip: "203.0.113.10", loc: "US", colo: "SJC", latencyMs: 140),
            v6Result: TraceProbeResult(label: "v6", url: "https://[2606:4700:4700::1111]/cdn-cgi/trace", ip: "3fff::99", loc: "CN", colo: "SHA", latencyMs: 28, isIPv6: true),
            dualResult: TraceProbeResult(label: "dual", url: "https://one.one.one.one/cdn-cgi/trace", ip: "203.0.113.10", loc: "US", colo: "SJC", latencyMs: 145)
        )
        let tempHist = IPHistoryStore(customFileURL: FileManager.default.temporaryDirectory.appendingPathComponent("test_\(UUID().uuidString).json"))
        defer { tempHist.clear() }

        let eval = GateEvaluator(
            netEnv: OfflineMockNetEnv(),
            procEnv: OfflineMockProcEnv(processes: []),
            prober: prober,
            historyStore: tempHist
        )

        let report = await eval.evaluateOpenGate(includeNetwork: true)
        #expect(report.verdict == .noGo)
        #expect(prober.claudeProbeCallCount == 0)
        #expect(report.checks.contains(where: { $0.id == "canary_ipv6_leak" && $0.severity == .fail }))
    }

    @Test("Open Gate: Returns GO on clean US residential exit with single static IP")
    func testCleanOpenGateGo() async {
        let prober = ConfigurableMockProber(
            v4Result: TraceProbeResult(label: "v4", url: "https://1.1.1.1/cdn-cgi/trace", ip: "203.0.113.10", loc: "US", colo: "SJC", latencyMs: 120),
            v6Result: TraceProbeResult(label: "v6", url: "https://[2606:4700:4700::1111]/cdn-cgi/trace", error: "Unreachable"),
            dualResult: TraceProbeResult(label: "dual", url: "https://one.one.one.one/cdn-cgi/trace", ip: "203.0.113.10", loc: "US", colo: "SJC", latencyMs: 120),
            claudeResult: TraceProbeResult(label: "claude", url: "https://claude.ai/cdn-cgi/trace", ip: "203.0.113.10", loc: "US", colo: "SJC", latencyMs: 135),
            anthropicResult: TraceProbeResult(label: "anth", url: "https://www.anthropic.com/cdn-cgi/trace", ip: "203.0.113.10", loc: "US", colo: "SJC", latencyMs: 138),
            riskSnapshot: IPRiskSnapshot(
                ip: "203.0.113.10",
                country: "United States",
                countryCode: "US",
                city: "San Jose",
                asn: 7922,
                asOrganization: "Comcast Cable",
                trustScore: 92,
                isResidential: true,
                isDatacenter: false,
                isVPN: false,
                isProxy: false,
                isTor: false,
                isCrawler: false,
                isAbuser: false,
                timezone: "America/Los_Angeles"
            )
        )
        let tempHist = IPHistoryStore(customFileURL: FileManager.default.temporaryDirectory.appendingPathComponent("test_\(UUID().uuidString).json"))
        defer { tempHist.clear() }

        let eval = GateEvaluator(
            netEnv: OfflineMockNetEnv(),
            procEnv: OfflineMockProcEnv(processes: []),
            prober: prober,
            historyStore: tempHist
        )

        let report = await eval.evaluateOpenGate(includeNetwork: true, sampleCount: 4)
        #expect(report.verdict == .go)
        #expect(prober.claudeProbeCallCount > 0)
        #expect(tempHist.load().first?.ip == "203.0.113.10")
    }

    @Test("Close Gate: Blocks on ShipIt / Claude Code CLI / unquiet log, passes when fully drained")
    func testCloseGateTripleBarrier() {
        let shipItProc = ClaudeProcessInfo(
            pid: 777,
            ppid: 1,
            kind: .shipItUpdater,
            executableName: "ShipIt",
            commandLine: "ShipIt com.anthropic.claudefordesktop.ShipIt",
            stateCode: "S"
        )
        let evalBlocked = GateEvaluator(
            netEnv: OfflineMockNetEnv(),
            procEnv: OfflineMockProcEnv(processes: [shipItProc]),
            prober: ConfigurableMockProber.inert()
        )
        let blockedReport = evalBlocked.evaluateCloseGate()
        #expect(blockedReport.status == .doNotCloseProxy)

        let evalDrained = GateEvaluator(
            netEnv: OfflineMockNetEnv(),
            procEnv: OfflineMockProcEnv(processes: []),
            prober: ConfigurableMockProber.inert()
        )
        let safeReport = evalDrained.evaluateCloseGate()
        #expect(safeReport.status == .safeToCloseProxy)
    }

    @Test("Close Gate: fails closed when the process table cannot be read")
    func testCloseGateProcessScanUnavailable() {
        let eval = GateEvaluator(
            netEnv: OfflineMockNetEnv(),
            procEnv: OfflineMockProcEnv(processes: [], processScanAvailable: false),
            prober: ConfigurableMockProber.inert()
        )
        let report = eval.evaluateCloseGate()
        #expect(report.status == .doNotCloseProxy)
        #expect(report.checks.contains { $0.id == "process_scan_failed" && $0.severity == .fail })
    }

    @Test("L7 Circuit Breaker: Real POSIX SIGSTOP freeze, SIGCONT resume, and SIGKILL zero-telemetry kill")
    func testCircuitBreakerRealProcessFreezeAndKill() throws {
        let sleepProc = Process()
        sleepProc.executableURL = URL(fileURLWithPath: "/bin/sleep")
        sleepProc.arguments = ["30"]
        try sleepProc.run()
        let childPID = sleepProc.processIdentifier
        defer {
            if sleepProc.isRunning {
                kill(childPID, SIGKILL)
            }
        }

        let syntheticInfo = ClaudeProcessInfo(
            pid: childPID,
            ppid: ProcessInfo.processInfo.processIdentifier,
            kind: .desktopMain,
            executableName: "Claude",
            commandLine: "/Applications/Claude.app/Contents/MacOS/Claude",
            stateCode: "S"
        )
        let mockProcEnv = OfflineMockProcEnv(processes: [syntheticInfo])
        let breaker = ActiveCircuitBreaker(
            netEnv: OfflineMockNetEnv(),
            procEnv: mockProcEnv,
            prober: ConfigurableMockProber.inert(),
            signaler: POSIXSignalController()
        )

        let freezeEvent = breaker.freezeAllClaudeProcesses(reason: "Test proxy drop")
        #expect(freezeEvent != nil)
        #expect(breaker.frozenPIDs.contains(childPID))

        // Verify directly via kernel waitpid(WUNTRACED) that child process entered SIGSTOP stopped state
        var waitStatus: Int32 = 0
        let wpid = waitpid(childPID, &waitStatus, WUNTRACED)
        #expect(wpid == childPID)
        #expect((waitStatus & 0x7f) == 0x7f) // _WSTATUS(x) == _WSTOPPED (0177)

        // Resume via SIGCONT
        let resumedCount = breaker.resumeFrozenProcesses()
        #expect(resumedCount == 1)
        #expect(sleepProc.isRunning == true)

        // Force kill via SIGKILL
        let killedCount = breaker.forceKillWithoutTelemetry()
        #expect(killedCount == 1)
        sleepProc.waitUntilExit()
        #expect(sleepProc.isRunning == false)
    }
}

// MARK: - Configurable Mock Prober

final class ConfigurableMockProber: NetworkProbing, @unchecked Sendable {
    let v4Result: TraceProbeResult
    let v6Result: TraceProbeResult
    let dualResult: TraceProbeResult
    let claudeResult: TraceProbeResult
    let anthropicResult: TraceProbeResult
    let riskSnapshot: IPRiskSnapshot?
    var claudeProbeCallCount = 0

    init(
        v4Result: TraceProbeResult,
        v6Result: TraceProbeResult,
        dualResult: TraceProbeResult,
        claudeResult: TraceProbeResult = TraceProbeResult(label: "c", url: "https://claude.ai/cdn-cgi/trace", error: "unused"),
        anthropicResult: TraceProbeResult = TraceProbeResult(label: "a", url: "https://www.anthropic.com/cdn-cgi/trace", error: "unused"),
        riskSnapshot: IPRiskSnapshot? = nil
    ) {
        self.v4Result = v4Result
        self.v6Result = v6Result
        self.dualResult = dualResult
        self.claudeResult = claudeResult
        self.anthropicResult = anthropicResult
        self.riskSnapshot = riskSnapshot
    }

    static func inert() -> ConfigurableMockProber {
        ConfigurableMockProber(
            v4Result: TraceProbeResult(label: "v4", url: "", error: "offline"),
            v6Result: TraceProbeResult(label: "v6", url: "", error: "offline"),
            dualResult: TraceProbeResult(label: "dual", url: "", error: "offline")
        )
    }

    func probeTrace(label: String, urlString: String, timeout: TimeInterval) async -> TraceProbeResult {
        if urlString.contains("1.1.1.1") { return v4Result }
        if urlString.contains("2606:4700") { return v6Result }
        if urlString.contains("one.one.one.one") { return dualResult }
        if urlString.contains("claude.ai") {
            claudeProbeCallCount += 1
            return claudeResult
        }
        if urlString.contains("anthropic.com") {
            claudeProbeCallCount += 1
            return anthropicResult
        }
        return v4Result
    }

    func sampleExitRotation(urlString: String, sampleCount: Int, timeout: TimeInterval) async -> [String] {
        claudeResult.ip.map { [$0] } ?? []
    }

    func fetchIPRisk(ip: String, timeout: TimeInterval) async -> IPRiskSnapshot? { riskSnapshot }
    func fetchGeoIP(ip: String, timeout: TimeInterval) async -> GeoIPSummary? {
        GeoIPSummary(ip: ip, country: "United States", countryCode: "US", region: "California", city: "San Jose", isp: "Comcast")
    }
    func fetchCNExitIP(timeout: TimeInterval) async -> String? { nil }
    func fetchClaudeServiceStatus(timeout: TimeInterval) async -> String? { "none" }
    func detectDNSLeak(claudeCountryCode: String?, timeout: TimeInterval) async -> DNSLeakResult {
        DNSLeakResult(checked: true, encryptedOrUnexposed: true, hasCNLeak: false, resolverIPs: [])
    }
    func detectUDPLeak(claudeExitIP: String?, timeout: TimeInterval) async -> UDPLeakResult {
        UDPLeakResult(checked: true, publicUDPIPs: claudeExitIP.map { [$0] } ?? [], matchesClaudeExit: true)
    }
}
