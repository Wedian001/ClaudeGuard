import Foundation

// MARK: - Human & JSON Report Formatter

public enum ReportFormatter {
    public static func encodeJSON<T: Encodable>(_ value: T) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(value),
              let str = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return str
    }

    public static func renderOpenReport(_ r: OpenGateReport, maskIP: Bool = false) -> String {
        var lines: [String] = []
        lines.append("══════════════════════════════════════════════════════════════")
        lines.append("  Claude Guard · 打开门禁诊断报告 (Open Gate)")
        lines.append("══════════════════════════════════════════════════════════════")
        lines.append("结论: \(r.verdict.badgeSymbol) \(r.verdict.rawValue) — \(r.summaryHeadline)")
        lines.append("建议: \(r.summaryAdvice)")
        lines.append("传输路径: \(r.transportMode.rawValue)")
        if let cf = r.canaryDomainTrace ?? r.canaryIPv4Trace, let ip = cf.ip {
            lines.append("Cloudflare 出口: \(RestrictedRegions.flagEmoji(for: cf.loc)) \(RestrictedRegions.maskIPAddress(ip, enabled: maskIP)) (\(cf.loc ?? "-"), \(cf.latencyMs)ms)")
        }
        if let ct = r.claudeTrace, let ip = ct.ip {
            lines.append("Claude 出口:     \(RestrictedRegions.flagEmoji(for: ct.loc)) \(RestrictedRegions.maskIPAddress(ip, enabled: maskIP)) (\(ct.loc ?? "-"), \(ct.latencyMs)ms)")
        }
        if let cn = r.cnExitIP {
            lines.append("中国大陆出口:    🇨🇳 \(RestrictedRegions.maskIPAddress(cn, enabled: maskIP)) (\(r.cnExitGeo?.formattedLocation ?? ""))")
        }
        if let risk = r.ipRisk {
            let scoreStr = risk.trustScore.map { "\($0)/100" } ?? "未知"
            lines.append("Trust Score:     \(scoreStr) · \(risk.purityLabel) · \(risk.ipTypeLabel) · \(risk.asOrganization ?? "-")")
        }
        lines.append("──────────────────────────────────────────────────────────────")
        for c in r.checks {
            lines.append(" \(c.severity.icon) [\(c.category)] \(c.title)")
            lines.append("    └─ \(c.detail)")
            if let rem = c.remediation {
                lines.append("    💡 \(rem)")
            }
        }
        lines.append("══════════════════════════════════════════════════════════════")
        return lines.joined(separator: "\n")
    }

    public static func renderCloseReport(_ r: CloseGateReport) -> String {
        var lines: [String] = []
        lines.append("══════════════════════════════════════════════════════════════")
        lines.append("  Claude Guard · 安全关闭代理检查 (Close Gate)")
        lines.append("══════════════════════════════════════════════════════════════")
        lines.append("结论: \(r.summaryHeadline)")
        lines.append("说明: \(r.summaryAdvice)")
        lines.append("──────────────────────────────────────────────────────────────")
        for c in r.checks {
            lines.append(" \(c.severity.icon) [\(c.category)] \(c.title)")
            lines.append("    └─ \(c.detail)")
            if let rem = c.remediation {
                lines.append("    💡 \(rem)")
            }
        }
        lines.append("══════════════════════════════════════════════════════════════")
        return lines.joined(separator: "\n")
    }
}

// MARK: - Built-in Offline Self-Test Suite (Zero Network)

public enum BuiltinSelfTest {
    public struct TestOutcome: Sendable {
        public let name: String
        public let passed: Bool
        public let detail: String
    }

    public static func runAll() async -> (allPassed: Bool, results: [TestOutcome]) {
        var outcomes: [TestOutcome] = []

        // 1. scutil --proxy + ExceptionsList bypass parsing
        let sampleScutil = """
        <dictionary> {
          ExceptionsList : <array> {
            0 : 127.0.0.1
            1 : localhost
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
        let parsedProxy = SystemProxyAndRouteInspector.parseScutilProxyOutput(sampleScutil)
        let proxyOk = parsedProxy.httpEnabled && parsedProxy.httpPort == 7890 &&
            parsedProxy.bypassedCriticalDomains.contains("browser-intake-us5-datadoghq.com") &&
            !parsedProxy.domainRoutingConsistent
        outcomes.append(TestOutcome(
            name: "系统代理与连字符遥测域名绕过检测",
            passed: proxyOk,
            detail: proxyOk ? "成功拦截 browser-intake-us5-datadoghq.com 绕过" : "解析失败"
        ))

        // 2. Mihomo split-route TUN & IPv6 leak route detection
        let utunRoute = """
           route to: 160.79.104.1
        destination: 128.0.0.0
               mask: 128.0.0.0
          interface: utun8
        """
        let en0V6Route = """
           route to: 2607:6bc0::1
          interface: en0
        """
        let ifconfigSample = """
        en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        \tinet6 fe80::1c2b:3a4d:5e6f:7a8b%en0 prefixlen 64 secured scopeid 0xe
        \tinet6 3fff:1234:5678::101 prefixlen 64 autoconf secured
        """
        let rV4 = SystemProxyAndRouteInspector.parseRouteGetOutput(utunRoute, target: "160.79.104.1")
        let rV6 = SystemProxyAndRouteInspector.parseRouteGetOutput(en0V6Route, target: "2607:6bc0::1")
        let pubV6 = SystemProxyAndRouteInspector.parsePhysicalPublicIPv6(from: ifconfigSample)
        let snap = KernelRouteSnapshot(
            defaultIPv4: RouteTargetCheck(target: "default", interfaceName: "en0", gateway: "192.168.1.1", isTunInterface: false),
            cloudflareIPv4: rV4,
            anthropicIPv4: rV4,
            anthropicIPv6: rV6,
            publicIPv6AddressesOnPhysical: pubV6
        )
        let routeOk = snap.isTunActiveForClaude && snap.hasIPv6DirectLeakRisk
        outcomes.append(TestOutcome(
            name: "Mihomo 细分前缀 TUN 识别与公网 IPv6 抢跑风险检测",
            passed: routeOk,
            detail: routeOk ? "default=en0 时仍精准识别 utun8，并捕获 3fff:: IPv6 泄露风险" : "路由判定异常"
        ))

        // 3. Full Claude family process classification (Desktop, ShipIt, CLI, excluding ClaudeGuard)
        let psSample = """
          101     1 Ss   /Applications/Claude.app/Contents/MacOS/Claude
          102   101 S    /Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper --type=utility
          103     1 S    /Applications/Claude.app/Contents/Frameworks/Squirrel.framework/Resources/ShipIt com.anthropic.claudefordesktop.ShipIt
          104   500 S+   /opt/homebrew/Caskroom/claude-code/2.1.139/claude
          105     1 S    /Applications/ClaudeGuard.app/Contents/MacOS/ClaudeGuardApp
        """
        let procs = ProcessAndSocketScanner.parsePSOutput(psSample, excludingPID: 99999)
        let kinds = Set(procs.map(\.kind))
        let procOk = procs.count == 4 &&
            kinds.contains(.desktopMain) &&
            kinds.contains(.desktopHelper) &&
            kinds.contains(.shipItUpdater) &&
            kinds.contains(.claudeCodeCLI)
        outcomes.append(TestOutcome(
            name: "全家桶进程识别（含 ShipIt 更新器、Claude Code CLI 及自身排除）",
            passed: procOk,
            detail: procOk ? "准确捕获 4 类目标进程并排除 ClaudeGuard 自身" : "捕获数量=\(procs.count)"
        ))

        // 4. RFC 5389 STUN XOR-MAPPED-ADDRESS IPv4 binary codec
        let txID: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        // Simulated IP 203.0.113.10 XORed with 0x21, 0x12, 0xA4, 0x42
        let ipRaw: [UInt8] = [203 ^ 0x21, 0 ^ 0x12, 113 ^ 0xA4, 10 ^ 0x42]
        var stunResp = Data([0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42])
        stunResp.append(contentsOf: txID)
        stunResp.append(contentsOf: [0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0x11, 0x22])
        stunResp.append(contentsOf: ipRaw)
        let decodedSTUN = STUNProbe.parseBindingResponse(stunResp, transactionID: txID)
        let stunOk = (decodedSTUN == "203.0.113.10")
        outcomes.append(TestOutcome(
            name: "RFC 5389 STUN XOR-MAPPED-ADDRESS 解码",
            passed: stunOk,
            detail: "解析结果: \(decodedSTUN ?? "nil")"
        ))

        // 5. Fail-Closed Canary Gate (CN canary MUST NEVER touch claude.ai)
        let mockProber = OfflineMockProber(canaryLoc: "CN", canaryIP: "192.0.2.53")
        let mockNet = OfflineMockNetEnv()
        let mockProc = OfflineMockProcEnv(processes: [])
        let tempHist = IPHistoryStore(customFileURL: FileManager.default.temporaryDirectory.appendingPathComponent("cg_selftest_\(UUID().uuidString).json"))
        let eval = GateEvaluator(netEnv: mockNet, procEnv: mockProc, prober: mockProber, historyStore: tempHist)
        let failClosedReport = await eval.evaluateOpenGate(includeNetwork: true)
        tempHist.clear()
        let failClosedOk = (failClosedReport.verdict == .noGo) && (mockProber.claudeDomainTouches == 0)
        outcomes.append(TestOutcome(
            name: "Fail-Closed 零泄露熔断（CN 出口绝不触碰 claude.ai）",
            passed: failClosedOk,
            detail: "verdict=\(failClosedReport.verdict.rawValue), claude.ai 请求次数=\(mockProber.claudeDomainTouches)"
        ))

        let allPass = outcomes.allSatisfy(\.passed)
        return (allPass, outcomes)
    }
}

// MARK: - Internal Mock Helpers for Self-Test

final class OfflineMockProber: NetworkProbing, @unchecked Sendable {
    let canaryLoc: String
    let canaryIP: String
    var claudeDomainTouches = 0

    init(canaryLoc: String, canaryIP: String) {
        self.canaryLoc = canaryLoc
        self.canaryIP = canaryIP
    }

    func probeTrace(label: String, urlString: String, timeout: TimeInterval) async -> TraceProbeResult {
        if urlString.contains("claude.ai") || urlString.contains("anthropic.com") {
            claudeDomainTouches += 1
        }
        if urlString.contains("2606:4700") {
            return TraceProbeResult(label: label, url: urlString, error: "IPv6 unreachable")
        }
        return TraceProbeResult(label: label, url: urlString, ip: canaryIP, loc: canaryLoc, colo: "SHA", latencyMs: 32)
    }

    func sampleExitRotation(urlString: String, sampleCount: Int, timeout: TimeInterval) async -> [String] {
        [canaryIP]
    }

    func fetchIPRisk(ip: String, timeout: TimeInterval) async -> IPRiskSnapshot? { nil }
    func fetchGeoIP(ip: String, timeout: TimeInterval) async -> GeoIPSummary? { nil }
    func fetchCNExitIP(timeout: TimeInterval) async -> String? { nil }
    func fetchClaudeServiceStatus(timeout: TimeInterval) async -> String? { nil }
    func detectDNSLeak(claudeCountryCode: String?, timeout: TimeInterval) async -> DNSLeakResult { DNSLeakResult() }
    func detectUDPLeak(claudeExitIP: String?, timeout: TimeInterval) async -> UDPLeakResult { UDPLeakResult() }
}

struct OfflineMockNetEnv: NetworkEnvironmentInspecting {
    func inspectProxySettings() -> ProxySettingsSnapshot { ProxySettingsSnapshot() }
    func inspectKernelRoutes() -> KernelRouteSnapshot {
        let r = RouteTargetCheck(target: "1.1.1.1", interfaceName: "utun8", gateway: nil, isTunInterface: true)
        return KernelRouteSnapshot(defaultIPv4: r, cloudflareIPv4: r, anthropicIPv4: r, anthropicIPv6: r, publicIPv6AddressesOnPhysical: [])
    }
    func scanInstalledProxyClients() -> [ProxyClientApp] { [] }
    func classifyTransportMode(proxy: ProxySettingsSnapshot, routes: KernelRouteSnapshot) -> TransportMode { .tunOnly }
}

struct OfflineMockProcEnv: ProcessAndEnvironmentInspecting {
    let processes: [ClaudeProcessInfo]
    var processScanAvailable: Bool = true

    init(processes: [ClaudeProcessInfo], processScanAvailable: Bool = true) {
        self.processes = processes
        self.processScanAvailable = processScanAvailable
    }

    func isClaudeDesktopInstalled() -> (installed: Bool, version: String?) { (true, "3.6556.2") }
    func scanClaudeProcesses() -> [ClaudeProcessInfo] { processes }
    func isProcessScanAvailable() -> Bool { processScanAvailable }
    func scanActiveSockets(claudePIDs: Set<Int32>) -> (claudeSockets: [ActiveSocketInfo], browserAnthropicSockets: [ActiveSocketInfo]) { ([], []) }
    func inspectClaudeLogs() -> LogScanResult { LogScanResult(mainLogExists: true, secondsSinceLastWrite: 10.0, isQuietFor2Seconds: true) }
    func inspectDeviceConsistency(exitCountryCode: String?, exitExactTimezone: String?) -> DeviceConsistencyResult {
        DeviceConsistencyResult(localTimezone: "America/Los_Angeles", localUTCOffsetMinutes: -420)
    }
}
