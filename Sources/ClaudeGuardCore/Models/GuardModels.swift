import Foundation

// MARK: - Core Verdict & Gate Enums

public enum VerdictLevel: String, Codable, Sendable, CaseIterable {
    case go = "GO"
    case goWithWarnings = "GO_WITH_WARNINGS"
    case noGo = "NO_GO"
    case frozenEmergency = "FROZEN_EMERGENCY"

    public var exitCode: Int32 {
        switch self {
        case .go: return 0
        case .goWithWarnings: return 1
        case .noGo, .frozenEmergency: return 2
        }
    }

    public var badgeSymbol: String {
        switch self {
        case .go: return "✅"
        case .goWithWarnings: return "⚠️"
        case .noGo: return "❌"
        case .frozenEmergency: return "❄️"
        }
    }

    public var titleText: String {
        switch self {
        case .go: return "安全放行（可打开 Claude）"
        case .goWithWarnings: return "允许打开（存在风险提示）"
        case .noGo: return "禁止打开（存在直连/受限风险）"
        case .frozenEmergency: return "已紧急冻结保护"
        }
    }
}

public enum ProxyCloseStatus: String, Codable, Sendable {
    case safeToCloseProxy = "SAFE_TO_CLOSE_PROXY"
    case doNotCloseProxy = "DO_NOT_CLOSE_PROXY"
    case frozenNeedsAction = "FROZEN_NEEDS_ACTION"

    public var exitCode: Int32 {
        switch self {
        case .safeToCloseProxy: return 0
        case .doNotCloseProxy, .frozenNeedsAction: return 2
        }
    }

    public var badgeSymbol: String {
        switch self {
        case .safeToCloseProxy: return "✅"
        case .doNotCloseProxy: return "❌"
        case .frozenNeedsAction: return "❄️"
        }
    }
}

public enum CheckSeverity: String, Codable, Sendable {
    case pass = "PASS"
    case info = "INFO"
    case warning = "WARN"
    case fail = "FAIL"

    public var icon: String {
        switch self {
        case .pass: return "✅"
        case .info: return "ℹ️"
        case .warning: return "⚠️"
        case .fail: return "❌"
        }
    }
}

public struct CheckItem: Identifiable, Codable, Sendable, Equatable {
    public var id: String
    public var category: String
    public var title: String
    public var severity: CheckSeverity
    public var detail: String
    public var remediation: String?

    public init(
        id: String,
        category: String,
        title: String,
        severity: CheckSeverity,
        detail: String,
        remediation: String? = nil
    ) {
        self.id = id
        self.category = category
        self.title = title
        self.severity = severity
        self.detail = detail
        self.remediation = remediation
    }
}

// MARK: - Process & Socket Models

public enum ClaudeProcessKind: String, Codable, Sendable {
    case desktopMain = "Claude Desktop 主进程"
    case desktopHelper = "Claude Helper 辅助进程"
    case shipItUpdater = "Squirrel/ShipIt 后台更新器"
    case chromeNativeHost = "Chrome 扩展通信宿主"
    case computerUseHelper = "Computer Use 辅助进程"
    case crashpadHandler = "Crashpad 崩溃上报进程"
    case claudeCodeCLI = "Claude Code CLI 终端会话"
    case sshAskPass = "Claude SSH AskPass"

    public var isDesktopAppFamily: Bool {
        switch self {
        case .desktopMain, .desktopHelper, .shipItUpdater, .computerUseHelper, .crashpadHandler, .sshAskPass:
            return true
        case .chromeNativeHost, .claudeCodeCLI:
            return false
        }
    }
}

public struct ClaudeProcessInfo: Identifiable, Codable, Sendable, Equatable {
    public var id: Int32 { pid }
    public var pid: Int32
    public var ppid: Int32
    public var kind: ClaudeProcessKind
    public var executableName: String
    public var commandLine: String
    public var stateCode: String

    public var isStopped: Bool {
        stateCode.uppercased().contains("T")
    }

    public init(
        pid: Int32,
        ppid: Int32,
        kind: ClaudeProcessKind,
        executableName: String,
        commandLine: String,
        stateCode: String
    ) {
        self.pid = pid
        self.ppid = ppid
        self.kind = kind
        self.executableName = executableName
        self.commandLine = commandLine
        self.stateCode = stateCode
    }
}

public struct ActiveSocketInfo: Identifiable, Codable, Sendable, Equatable {
    public var id: String { "\(pid)-\(protocolName)-\(localEndpoint)->\(remoteEndpoint)" }
    public var pid: Int32
    public var processName: String
    public var protocolName: String
    public var localEndpoint: String
    public var remoteEndpoint: String
    public var state: String
    public var isClaudeFamilyProcess: Bool
    public var isAnthropicIPRange: Bool
    public var isBrowserProcess: Bool

    public init(
        pid: Int32,
        processName: String,
        protocolName: String,
        localEndpoint: String,
        remoteEndpoint: String,
        state: String,
        isClaudeFamilyProcess: Bool,
        isAnthropicIPRange: Bool,
        isBrowserProcess: Bool
    ) {
        self.pid = pid
        self.processName = processName
        self.protocolName = protocolName
        self.localEndpoint = localEndpoint
        self.remoteEndpoint = remoteEndpoint
        self.state = state
        self.isClaudeFamilyProcess = isClaudeFamilyProcess
        self.isAnthropicIPRange = isAnthropicIPRange
        self.isBrowserProcess = isBrowserProcess
    }
}

// MARK: - Proxy & Kernel Route Models

public enum TransportMode: String, Codable, Sendable {
    case tunAndSystemProxy = "TUN + 系统代理双保险"
    case tunOnly = "TUN 虚拟网卡接管"
    case systemProxyOnly = "系统 HTTP/HTTPS 代理"
    case pacAutoProxy = "PAC 自动代理脚本"
    case socksOnly = "仅系统 SOCKS5 代理"
    case directNoProxy = "直连（未检测到代理/TUN）"

    public var isProtectedLocally: Bool {
        switch self {
        case .tunAndSystemProxy, .tunOnly, .systemProxyOnly, .pacAutoProxy, .socksOnly:
            return true
        case .directNoProxy:
            return false
        }
    }
}

public struct ProxySettingsSnapshot: Codable, Sendable, Equatable {
    public var httpEnabled: Bool
    public var httpHost: String?
    public var httpPort: Int?
    public var httpsEnabled: Bool
    public var httpsHost: String?
    public var httpsPort: Int?
    public var socksEnabled: Bool
    public var socksHost: String?
    public var socksPort: Int?
    public var pacEnabled: Bool
    public var pacURL: String?
    public var exceptionsList: [String]
    public var domainRoutingConsistent: Bool
    public var bypassedCriticalDomains: [String]

    public var hasExplicitHTTPProxy: Bool {
        (httpEnabled && httpHost != nil && (httpPort ?? 0) > 0) ||
        (httpsEnabled && httpsHost != nil && (httpsPort ?? 0) > 0)
    }

    public var primaryProxyDisplay: String? {
        if httpsEnabled, let h = httpsHost, let p = httpsPort {
            return "HTTPS \(h):\(p)"
        }
        if httpEnabled, let h = httpHost, let p = httpPort {
            return "HTTP \(h):\(p)"
        }
        if socksEnabled, let h = socksHost, let p = socksPort {
            return "SOCKS5 \(h):\(p)"
        }
        if pacEnabled, let url = pacURL {
            return "PAC (\(url))"
        }
        return nil
    }

    public init(
        httpEnabled: Bool = false,
        httpHost: String? = nil,
        httpPort: Int? = nil,
        httpsEnabled: Bool = false,
        httpsHost: String? = nil,
        httpsPort: Int? = nil,
        socksEnabled: Bool = false,
        socksHost: String? = nil,
        socksPort: Int? = nil,
        pacEnabled: Bool = false,
        pacURL: String? = nil,
        exceptionsList: [String] = [],
        domainRoutingConsistent: Bool = true,
        bypassedCriticalDomains: [String] = []
    ) {
        self.httpEnabled = httpEnabled
        self.httpHost = httpHost
        self.httpPort = httpPort
        self.httpsEnabled = httpsEnabled
        self.httpsHost = httpsHost
        self.httpsPort = httpsPort
        self.socksEnabled = socksEnabled
        self.socksHost = socksHost
        self.socksPort = socksPort
        self.pacEnabled = pacEnabled
        self.pacURL = pacURL
        self.exceptionsList = exceptionsList
        self.domainRoutingConsistent = domainRoutingConsistent
        self.bypassedCriticalDomains = bypassedCriticalDomains
    }
}

public struct RouteTargetCheck: Codable, Sendable, Equatable {
    public var target: String
    public var interfaceName: String?
    public var gateway: String?
    public var isTunInterface: Bool

    public init(target: String, interfaceName: String?, gateway: String?, isTunInterface: Bool) {
        self.target = target
        self.interfaceName = interfaceName
        self.gateway = gateway
        self.isTunInterface = isTunInterface
    }
}

public struct KernelRouteSnapshot: Codable, Sendable, Equatable {
    public var defaultIPv4: RouteTargetCheck
    public var cloudflareIPv4: RouteTargetCheck
    public var anthropicIPv4: RouteTargetCheck
    public var anthropicIPv6: RouteTargetCheck
    public var publicIPv6AddressesOnPhysical: [String]

    public var isTunActiveForClaude: Bool {
        anthropicIPv4.isTunInterface || cloudflareIPv4.isTunInterface
    }

    /// True if physical NIC has global IPv6 and Anthropic IPv6 route goes out physical NIC instead of utun
    public var hasIPv6DirectLeakRisk: Bool {
        guard !publicIPv6AddressesOnPhysical.isEmpty else { return false }
        guard let iface = anthropicIPv6.interfaceName, !iface.isEmpty else { return false }
        return !anthropicIPv6.isTunInterface
    }

    public init(
        defaultIPv4: RouteTargetCheck,
        cloudflareIPv4: RouteTargetCheck,
        anthropicIPv4: RouteTargetCheck,
        anthropicIPv6: RouteTargetCheck,
        publicIPv6AddressesOnPhysical: [String]
    ) {
        self.defaultIPv4 = defaultIPv4
        self.cloudflareIPv4 = cloudflareIPv4
        self.anthropicIPv4 = anthropicIPv4
        self.anthropicIPv6 = anthropicIPv6
        self.publicIPv6AddressesOnPhysical = publicIPv6AddressesOnPhysical
    }
}

public struct ProxyClientApp: Identifiable, Codable, Sendable, Equatable {
    public var id: String { path }
    public var name: String
    public var bundleID: String
    public var path: String
    public var isRunning: Bool

    public init(name: String, bundleID: String, path: String, isRunning: Bool) {
        self.name = name
        self.bundleID = bundleID
        self.path = path
        self.isRunning = isRunning
    }
}

// MARK: - Network Probe & Risk Models

public struct TraceProbeResult: Codable, Sendable, Equatable {
    public var label: String
    public var url: String
    public var ip: String?
    public var loc: String?
    public var colo: String?
    public var httpVersion: String?
    public var tlsVersion: String?
    public var latencyMs: Int
    public var isIPv6: Bool
    public var error: String?

    public var succeeded: Bool {
        ip != nil && error == nil
    }

    public var restrictedRegionName: String? {
        guard let code = loc?.uppercased() else { return nil }
        return RestrictedRegions.restrictedCountryNames[code]
    }

    public init(
        label: String,
        url: String,
        ip: String? = nil,
        loc: String? = nil,
        colo: String? = nil,
        httpVersion: String? = nil,
        tlsVersion: String? = nil,
        latencyMs: Int = 0,
        isIPv6: Bool = false,
        error: String? = nil
    ) {
        self.label = label
        self.url = url
        self.ip = ip
        self.loc = loc
        self.colo = colo
        self.httpVersion = httpVersion
        self.tlsVersion = tlsVersion
        self.latencyMs = latencyMs
        self.isIPv6 = isIPv6
        self.error = error
    }
}

public struct GeoIPSummary: Codable, Sendable, Equatable {
    public var ip: String
    public var country: String?
    public var countryCode: String?
    public var region: String?
    public var city: String?
    public var isp: String?

    public var formattedLocation: String {
        [country, region, city, isp].compactMap { $0?.isEmpty == false ? $0 : nil }.joined(separator: " · ")
    }

    public init(
        ip: String,
        country: String? = nil,
        countryCode: String? = nil,
        region: String? = nil,
        city: String? = nil,
        isp: String? = nil
    ) {
        self.ip = ip
        self.country = country
        self.countryCode = countryCode
        self.region = region
        self.city = city
        self.isp = isp
    }
}

public struct IPRiskSnapshot: Codable, Sendable, Equatable {
    public var ip: String
    public var country: String?
    public var countryCode: String?
    public var region: String?
    public var city: String?
    public var asn: Int?
    public var asOrganization: String?
    public var trustScore: Int?
    public var isResidential: Bool?
    public var isBroadcast: Bool?
    public var isDatacenter: Bool?
    public var isVPN: Bool?
    public var isProxy: Bool?
    public var isTor: Bool?
    public var isCrawler: Bool?
    public var isAbuser: Bool?
    public var companyType: String?
    public var companyName: String?
    public var timezone: String?

    public var purityLabel: String {
        if let cc = countryCode?.uppercased(), RestrictedRegions.restrictedCountryNames[cc] != nil {
            return "受限地区 (0分)"
        }
        guard let score = trustScore else { return "暂无评分" }
        switch score {
        case 95...: return "极度纯净"
        case 80..<95: return "纯净"
        case 50..<80: return "良好"
        case 25..<50: return "中性偏低"
        default: return "高危可疑"
        }
    }

    public var ipTypeLabel: String {
        if isResidential == true { return "家庭住宅 IP" }
        if isDatacenter == true || isResidential == false { return "机房 Hosting IP" }
        return "未知类型"
    }

    public init(
        ip: String,
        country: String? = nil,
        countryCode: String? = nil,
        region: String? = nil,
        city: String? = nil,
        asn: Int? = nil,
        asOrganization: String? = nil,
        trustScore: Int? = nil,
        isResidential: Bool? = nil,
        isBroadcast: Bool? = nil,
        isDatacenter: Bool? = nil,
        isVPN: Bool? = nil,
        isProxy: Bool? = nil,
        isTor: Bool? = nil,
        isCrawler: Bool? = nil,
        isAbuser: Bool? = nil,
        companyType: String? = nil,
        companyName: String? = nil,
        timezone: String? = nil
    ) {
        self.ip = ip
        self.country = country
        self.countryCode = countryCode
        self.region = region
        self.city = city
        self.asn = asn
        self.asOrganization = asOrganization
        self.trustScore = trustScore
        self.isResidential = isResidential
        self.isBroadcast = isBroadcast
        self.isDatacenter = isDatacenter
        self.isVPN = isVPN
        self.isProxy = isProxy
        self.isTor = isTor
        self.isCrawler = isCrawler
        self.isAbuser = isAbuser
        self.companyType = companyType
        self.companyName = companyName
        self.timezone = timezone
    }
}

public struct DNSLeakResult: Codable, Sendable, Equatable {
    public var checked: Bool
    public var encryptedOrUnexposed: Bool
    public var hasCNLeak: Bool
    public var resolverIPs: [String]
    public var primaryResolverGeo: GeoIPSummary?

    public init(
        checked: Bool = false,
        encryptedOrUnexposed: Bool = false,
        hasCNLeak: Bool = false,
        resolverIPs: [String] = [],
        primaryResolverGeo: GeoIPSummary? = nil
    ) {
        self.checked = checked
        self.encryptedOrUnexposed = encryptedOrUnexposed
        self.hasCNLeak = hasCNLeak
        self.resolverIPs = resolverIPs
        self.primaryResolverGeo = primaryResolverGeo
    }
}

public struct UDPLeakResult: Codable, Sendable, Equatable {
    public var checked: Bool
    public var publicUDPIPs: [String]
    public var matchesClaudeExit: Bool
    public var leakedIP: String?
    public var leakedGeo: GeoIPSummary?

    public init(
        checked: Bool = false,
        publicUDPIPs: [String] = [],
        matchesClaudeExit: Bool = true,
        leakedIP: String? = nil,
        leakedGeo: GeoIPSummary? = nil
    ) {
        self.checked = checked
        self.publicUDPIPs = publicUDPIPs
        self.matchesClaudeExit = matchesClaudeExit
        self.leakedIP = leakedIP
        self.leakedGeo = leakedGeo
    }
}

public struct DeviceConsistencyResult: Codable, Sendable, Equatable {
    public var localTimezone: String
    public var localUTCOffsetMinutes: Int
    public var exitTimezone: String?
    public var exitTimezoneIsEstimated: Bool
    public var exitUTCOffsetMinutes: Int?
    public var timezoneMatched: Bool?
    public var isChinaMainlandTimezone: Bool
    public var appleLanguages: [String]
    public var primaryLanguageCode: String
    public var expectedRegionLanguages: [String]
    public var languageMatched: Bool?

    public init(
        localTimezone: String,
        localUTCOffsetMinutes: Int,
        exitTimezone: String? = nil,
        exitTimezoneIsEstimated: Bool = false,
        exitUTCOffsetMinutes: Int? = nil,
        timezoneMatched: Bool? = nil,
        isChinaMainlandTimezone: Bool = false,
        appleLanguages: [String] = [],
        primaryLanguageCode: String = "",
        expectedRegionLanguages: [String] = [],
        languageMatched: Bool? = nil
    ) {
        self.localTimezone = localTimezone
        self.localUTCOffsetMinutes = localUTCOffsetMinutes
        self.exitTimezone = exitTimezone
        self.exitTimezoneIsEstimated = exitTimezoneIsEstimated
        self.exitUTCOffsetMinutes = exitUTCOffsetMinutes
        self.timezoneMatched = timezoneMatched
        self.isChinaMainlandTimezone = isChinaMainlandTimezone
        self.appleLanguages = appleLanguages
        self.primaryLanguageCode = primaryLanguageCode
        self.expectedRegionLanguages = expectedRegionLanguages
        self.languageMatched = languageMatched
    }
}

public struct LogScanResult: Codable, Sendable, Equatable {
    public var mainLogExists: Bool
    public var secondsSinceLastWrite: Double?
    public var isQuietFor2Seconds: Bool
    public var lastQuitMarker: String?
    public var recentRegionUnavailableCount: Int
    public var recentAuth403Count: Int
    public var latestErrorLine: String?

    public init(
        mainLogExists: Bool = false,
        secondsSinceLastWrite: Double? = nil,
        isQuietFor2Seconds: Bool = true,
        lastQuitMarker: String? = nil,
        recentRegionUnavailableCount: Int = 0,
        recentAuth403Count: Int = 0,
        latestErrorLine: String? = nil
    ) {
        self.mainLogExists = mainLogExists
        self.secondsSinceLastWrite = secondsSinceLastWrite
        self.isQuietFor2Seconds = isQuietFor2Seconds
        self.lastQuitMarker = lastQuitMarker
        self.recentRegionUnavailableCount = recentRegionUnavailableCount
        self.recentAuth403Count = recentAuth403Count
        self.latestErrorLine = latestErrorLine
    }
}

// MARK: - Aggregated Gate Reports

public struct OpenGateReport: Codable, Sendable, Equatable {
    public var timestamp: Date
    public var claudeInstalled: Bool
    public var claudeVersion: String?
    public var verdict: VerdictLevel
    public var transportMode: TransportMode
    public var proxySnapshot: ProxySettingsSnapshot
    public var routeSnapshot: KernelRouteSnapshot
    public var proxyClients: [ProxyClientApp]
    public var canaryIPv4Trace: TraceProbeResult?
    public var canaryIPv6Trace: TraceProbeResult?
    public var canaryDomainTrace: TraceProbeResult?
    public var claudeTrace: TraceProbeResult?
    public var anthropicTrace: TraceProbeResult?
    public var cnExitIP: String?
    public var cnExitGeo: GeoIPSummary?
    public var cfExitGeo: GeoIPSummary?
    public var claudeExitGeo: GeoIPSummary?
    public var ipRisk: IPRiskSnapshot?
    public var rotationUniqueIPs: [String]
    public var rotationSampleCount: Int
    public var dnsLeak: DNSLeakResult
    public var udpLeak: UDPLeakResult
    public var claudeServiceIndicator: String?
    public var deviceConsistency: DeviceConsistencyResult
    public var logScan: LogScanResult
    public var checks: [CheckItem]
    public var summaryHeadline: String
    public var summaryAdvice: String

    public init(
        timestamp: Date = Date(),
        claudeInstalled: Bool,
        claudeVersion: String?,
        verdict: VerdictLevel,
        transportMode: TransportMode,
        proxySnapshot: ProxySettingsSnapshot,
        routeSnapshot: KernelRouteSnapshot,
        proxyClients: [ProxyClientApp],
        canaryIPv4Trace: TraceProbeResult? = nil,
        canaryIPv6Trace: TraceProbeResult? = nil,
        canaryDomainTrace: TraceProbeResult? = nil,
        claudeTrace: TraceProbeResult? = nil,
        anthropicTrace: TraceProbeResult? = nil,
        cnExitIP: String? = nil,
        cnExitGeo: GeoIPSummary? = nil,
        cfExitGeo: GeoIPSummary? = nil,
        claudeExitGeo: GeoIPSummary? = nil,
        ipRisk: IPRiskSnapshot? = nil,
        rotationUniqueIPs: [String] = [],
        rotationSampleCount: Int = 0,
        dnsLeak: DNSLeakResult = DNSLeakResult(),
        udpLeak: UDPLeakResult = UDPLeakResult(),
        claudeServiceIndicator: String? = nil,
        deviceConsistency: DeviceConsistencyResult,
        logScan: LogScanResult,
        checks: [CheckItem],
        summaryHeadline: String,
        summaryAdvice: String
    ) {
        self.timestamp = timestamp
        self.claudeInstalled = claudeInstalled
        self.claudeVersion = claudeVersion
        self.verdict = verdict
        self.transportMode = transportMode
        self.proxySnapshot = proxySnapshot
        self.routeSnapshot = routeSnapshot
        self.proxyClients = proxyClients
        self.canaryIPv4Trace = canaryIPv4Trace
        self.canaryIPv6Trace = canaryIPv6Trace
        self.canaryDomainTrace = canaryDomainTrace
        self.claudeTrace = claudeTrace
        self.anthropicTrace = anthropicTrace
        self.cnExitIP = cnExitIP
        self.cnExitGeo = cnExitGeo
        self.cfExitGeo = cfExitGeo
        self.claudeExitGeo = claudeExitGeo
        self.ipRisk = ipRisk
        self.rotationUniqueIPs = rotationUniqueIPs
        self.rotationSampleCount = rotationSampleCount
        self.dnsLeak = dnsLeak
        self.udpLeak = udpLeak
        self.claudeServiceIndicator = claudeServiceIndicator
        self.deviceConsistency = deviceConsistency
        self.logScan = logScan
        self.checks = checks
        self.summaryHeadline = summaryHeadline
        self.summaryAdvice = summaryAdvice
    }
}

public struct CloseGateReport: Codable, Sendable, Equatable {
    public var timestamp: Date
    public var status: ProxyCloseStatus
    public var processes: [ClaudeProcessInfo]
    public var claudeSockets: [ActiveSocketInfo]
    public var browserAnthropicSockets: [ActiveSocketInfo]
    public var logScan: LogScanResult
    public var proxyClients: [ProxyClientApp]
    public var checks: [CheckItem]
    public var summaryHeadline: String
    public var summaryAdvice: String

    public var isSafeToCloseProxy: Bool {
        status == .safeToCloseProxy
    }

    public init(
        timestamp: Date = Date(),
        status: ProxyCloseStatus,
        processes: [ClaudeProcessInfo],
        claudeSockets: [ActiveSocketInfo],
        browserAnthropicSockets: [ActiveSocketInfo],
        logScan: LogScanResult,
        proxyClients: [ProxyClientApp],
        checks: [CheckItem],
        summaryHeadline: String,
        summaryAdvice: String
    ) {
        self.timestamp = timestamp
        self.status = status
        self.processes = processes
        self.claudeSockets = claudeSockets
        self.browserAnthropicSockets = browserAnthropicSockets
        self.logScan = logScan
        self.proxyClients = proxyClients
        self.checks = checks
        self.summaryHeadline = summaryHeadline
        self.summaryAdvice = summaryAdvice
    }
}

public struct IPHistoryEntry: Identifiable, Codable, Sendable, Equatable {
    public var id: String { "\(ip)-\(Int(timestamp.timeIntervalSince1970))" }
    public var timestamp: Date
    public var ip: String
    public var countryCode: String?
    public var location: String
    public var asnOrg: String?
    public var trustScore: Int?
    public var isResidential: Bool?

    public init(
        timestamp: Date = Date(),
        ip: String,
        countryCode: String?,
        location: String,
        asnOrg: String?,
        trustScore: Int?,
        isResidential: Bool?
    ) {
        self.timestamp = timestamp
        self.ip = ip
        self.countryCode = countryCode
        self.location = location
        self.asnOrg = asnOrg
        self.trustScore = trustScore
        self.isResidential = isResidential
    }
}

// MARK: - Domain & Region Reference Tables

public enum RestrictedRegions {
    public static let restrictedCountryNames: [String: String] = [
        "CN": "中国大陆",
        "HK": "中国香港",
        "MO": "中国澳门",
        "RU": "俄罗斯",
        "KP": "朝鲜",
        "IR": "伊朗",
        "SY": "叙利亚",
        "CU": "古巴",
        "BY": "白俄罗斯",
        "VE": "委内瑞拉"
    ]

    public static let criticalClaudeDomains: [String] = [
        "claude.ai",
        "api.anthropic.com",
        "www.anthropic.com",
        "claude.com",
        "claudemcpclient.com",
        "claudeusercontent.com",
        "anthropic.auth0.com",
        "statsigapi.net",
        "sentry.io",
        "browser-intake-us5-datadoghq.com"
    ]

    public static let countryToRepresentativeTimezone: [String: String] = [
        "CN": "Asia/Shanghai", "TW": "Asia/Taipei", "HK": "Asia/Hong_Kong", "MO": "Asia/Macau",
        "JP": "Asia/Tokyo", "KR": "Asia/Seoul", "SG": "Asia/Singapore", "MY": "Asia/Kuala_Lumpur",
        "TH": "Asia/Bangkok", "VN": "Asia/Ho_Chi_Minh", "ID": "Asia/Jakarta", "PH": "Asia/Manila",
        "IN": "Asia/Kolkata", "IL": "Asia/Jerusalem", "AE": "Asia/Dubai", "TR": "Europe/Istanbul",
        "GB": "Europe/London", "IE": "Europe/Dublin", "FR": "Europe/Paris", "DE": "Europe/Berlin",
        "IT": "Europe/Rome", "ES": "Europe/Madrid", "NL": "Europe/Amsterdam", "CH": "Europe/Zurich",
        "SE": "Europe/Stockholm", "NO": "Europe/Oslo", "FI": "Europe/Helsinki", "PL": "Europe/Warsaw",
        "US": "America/Los_Angeles", "CA": "America/Toronto", "MX": "America/Mexico_City",
        "BR": "America/Sao_Paulo", "AR": "America/Argentina/Buenos_Aires",
        "AU": "Australia/Sydney", "NZ": "Pacific/Auckland", "ZA": "Africa/Johannesburg"
    ]

    public static let countryToAcceptedLanguages: [String: [String]] = [
        "CN": ["zh"], "TW": ["zh"], "HK": ["zh", "en"], "MO": ["zh", "en"],
        "JP": ["ja"], "KR": ["ko"], "TH": ["th"], "VN": ["vi"],
        "SG": ["en", "zh", "ms", "ta"], "MY": ["ms", "en", "zh", "ta"],
        "ID": ["id", "en"], "PH": ["en", "tl", "fil"], "IN": ["en", "hi"],
        "US": ["en"], "GB": ["en"], "IE": ["en", "ga"], "AU": ["en"], "NZ": ["en", "mi"],
        "CA": ["en", "fr"], "DE": ["de"], "AT": ["de"], "CH": ["de", "fr", "it", "rm"],
        "FR": ["fr"], "IT": ["it"], "ES": ["es", "ca"], "PT": ["pt"], "NL": ["nl"],
        "SE": ["sv"], "NO": ["no", "nb", "nn"], "DK": ["da"], "FI": ["fi", "sv"],
        "PL": ["pl"], "TR": ["tr"], "BR": ["pt"], "MX": ["es"], "AR": ["es"]
    ]

    public static func flagEmoji(for countryCode: String?) -> String {
        guard let cc = countryCode?.uppercased(), cc.count == 2 else { return "🌐" }
        let base: UInt32 = 127397
        var scalars = String.UnicodeScalarView()
        for scalar in cc.unicodeScalars {
            guard scalar.value >= 65 && scalar.value <= 90,
                  let regional = UnicodeScalar(base + scalar.value) else {
                return "🌐"
            }
            scalars.append(regional)
        }
        return String(scalars)
    }

    public static func maskIPAddress(_ ip: String, enabled: Bool) -> String {
        guard enabled, !ip.isEmpty else { return ip }
        if ip.contains(":") {
            let parts = ip.split(separator: ":", omittingEmptySubsequences: false)
            if parts.count >= 3 {
                return "\(parts[0]):\(parts[1]):*:*:*"
            }
            return "****:****"
        } else {
            let parts = ip.split(separator: ".")
            if parts.count == 4 {
                return "\(parts[0]).\(parts[1]).*.*"
            }
            return ip
        }
    }
}
