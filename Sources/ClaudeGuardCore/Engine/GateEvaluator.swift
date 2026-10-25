import Foundation

public final class IPHistoryStore: Sendable {
    private let fileURL: URL

    public init(customFileURL: URL? = nil) {
        if let customFileURL {
            self.fileURL = customFileURL
        } else {
            let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
                ?? URL(fileURLWithPath: (NSHomeDirectory() as NSString).appendingPathComponent("Library/Application Support"))
            let dir = appSupport.appendingPathComponent("ClaudeGuard", isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            self.fileURL = dir.appendingPathComponent("ip_history.json")
        }
    }

    public func load() -> [IPHistoryEntry] {
        guard let data = try? Data(contentsOf: fileURL) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([IPHistoryEntry].self, from: data)) ?? []
    }

    public func record(_ entry: IPHistoryEntry, maxEntries: Int = 20) {
        var list = load()
        // Deduplicate if top entry has identical IP within 10 minutes
        if let first = list.first, first.ip == entry.ip, abs(first.timestamp.timeIntervalSince(entry.timestamp)) < 600 {
            list[0] = entry
        } else {
            list.insert(entry, at: 0)
        }
        if list.count > maxEntries {
            list = Array(list.prefix(maxEntries))
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        if let data = try? encoder.encode(list) {
            try? data.write(to: fileURL, options: .atomic)
        }
    }

    public func clear() {
        try? FileManager.default.removeItem(at: fileURL)
    }
}

public struct GateEvaluator: Sendable {
    public let netEnv: any NetworkEnvironmentInspecting
    public let procEnv: any ProcessAndEnvironmentInspecting
    public let prober: any NetworkProbing
    public let historyStore: IPHistoryStore

    public init(
        netEnv: any NetworkEnvironmentInspecting = SystemProxyAndRouteInspector(),
        procEnv: any ProcessAndEnvironmentInspecting = ProcessAndSocketScanner(),
        prober: any NetworkProbing = LiveNetworkProbeService(),
        historyStore: IPHistoryStore = IPHistoryStore()
    ) {
        self.netEnv = netEnv
        self.procEnv = procEnv
        self.prober = prober
        self.historyStore = historyStore
    }

    // MARK: - Open Gate Evaluation (Fail-Closed)

    public func evaluateOpenGate(
        includeNetwork: Bool = true,
        deep: Bool = false,
        sampleCount: Int = 6,
        timeout: TimeInterval = 5.0,
        onStep: (@Sendable (String) -> Void)? = nil
    ) async -> OpenGateReport {
        onStep?("正在读取本地路由表、系统代理与 Claude 环境...")
        let appInfo = procEnv.isClaudeDesktopInstalled()
        let proxySnap = netEnv.inspectProxySettings()
        let routeSnap = netEnv.inspectKernelRoutes()
        let transport = netEnv.classifyTransportMode(proxy: proxySnap, routes: routeSnap)
        let proxyClients = netEnv.scanInstalledProxyClients()
        let logScan = procEnv.inspectClaudeLogs()

        var checks: [CheckItem] = []

        if appInfo.installed {
            checks.append(CheckItem(
                id: "app_installed",
                category: "本地环境",
                title: "Claude Desktop 安装状态",
                severity: .pass,
                detail: "已安装 /Applications/Claude.app（版本 \(appInfo.version ?? "未知")）"
            ))
        } else {
            checks.append(CheckItem(
                id: "app_installed",
                category: "本地环境",
                title: "未检测到 Claude Desktop",
                severity: .warning,
                detail: "/Applications/Claude.app 不存在（仍可执行出口网络诊断）",
                remediation: "请确认 Claude Desktop 已安装至 /Applications/Claude.app"
            ))
        }

        // Check system proxy domain consistency (e.g. ExceptionsList bypassing datadog/anthropic)
        if !proxySnap.domainRoutingConsistent || !proxySnap.bypassedCriticalDomains.isEmpty {
            let bypassedStr = proxySnap.bypassedCriticalDomains.joined(separator: ", ")
            checks.append(CheckItem(
                id: "proxy_domain_consistency",
                category: "分流完整性",
                title: "系统代理绕过了关键 Claude/遥测域名",
                severity: .fail,
                detail: "以下关键域名被绕过或分流不一致：\(bypassedStr)",
                remediation: "请从系统代理忽略列表 (ExceptionsList) 或 PAC 直连规则中移除上述域名"
            ))
        } else {
            checks.append(CheckItem(
                id: "transport_mode",
                category: "传输路径",
                title: "本地代理传输路径",
                severity: transport.isProtectedLocally ? .pass : .warning,
                detail: "\(transport.rawValue)" + (proxySnap.primaryProxyDisplay.map { " · \($0)" } ?? "") + (routeSnap.anthropicIPv4.interfaceName.map { " · 路由出口 \($0)" } ?? "")
            ))
        }

        if routeSnap.hasIPv6DirectLeakRisk {
            checks.append(CheckItem(
                id: "ipv6_route_leak_risk",
                category: "双栈防泄露",
                title: "本机物理网卡存在公网 IPv6 且未进 TUN",
                severity: .warning,
                detail: "Anthropic IPv6 段 (2607:6bc0::/32) 指向物理网卡 \(routeSnap.anthropicIPv6.interfaceName ?? "en0")",
                remediation: "强烈建议在代理客户端开启 IPv6 接管或关闭 Wi-Fi/以太网的原生 IPv6，防止 Happy Eyeballs 抢跑泄露"
            ))
        }

        // Fast local-only mode (no network packets sent)
        if !includeNetwork {
            let initDevice = procEnv.inspectDeviceConsistency(exitCountryCode: nil, exitExactTimezone: nil)
            let localVerdict: VerdictLevel
            if checks.contains(where: { $0.severity == .fail }) || !transport.isProtectedLocally {
                localVerdict = .noGo
            } else {
                localVerdict = .goWithWarnings
            }
            let headline = localVerdict == .noGo
                ? "本地未检测到有效代理或 TUN 路由，禁止打开 Claude"
                : "本地已检测到 \(transport.rawValue)（点击安全打开将自动执行实时出口复核）"
            let advice = localVerdict == .noGo
                ? Self.formatProxyClientHint(proxyClients)
                : "仅本地状态正常，启动 Claude 前必须完成一次无害出口探测以防假 TUN 断流。"

            return OpenGateReport(
                claudeInstalled: appInfo.installed,
                claudeVersion: appInfo.version,
                verdict: localVerdict,
                transportMode: transport,
                proxySnapshot: proxySnap,
                routeSnapshot: routeSnap,
                proxyClients: proxyClients,
                deviceConsistency: initDevice,
                logScan: logScan,
                checks: checks,
                summaryHeadline: headline,
                summaryAdvice: advice
            )
        }

        // Step 2: Harmless Dual-Stack Canary Probe (1.1.1.1 IPv4 + [2606:4700:4700::1111] IPv6 + one.one.one.one DualStack)
        // NEVER touches claude.ai before confirming safe overseas exit on ALL active stacks!
        onStep?("正在探测通用无害双栈出口 (Cloudflare IPv4 / IPv6)...")
        async let v4Task = prober.probeTrace(label: "Cloudflare IPv4", urlString: "https://1.1.1.1/cdn-cgi/trace", timeout: timeout)
        async let dualTask = prober.probeTrace(label: "Cloudflare 双栈域名", urlString: "https://one.one.one.one/cdn-cgi/trace", timeout: timeout)
        async let v6Task = prober.probeTrace(label: "Cloudflare IPv6", urlString: "https://[2606:4700:4700::1111]/cdn-cgi/trace", timeout: min(timeout, 2.5))

        let (canaryV4, canaryDual, canaryV6) = await (v4Task, dualTask, v6Task)

        // Fail-Closed Check 2A: Network reachability
        if !canaryV4.succeeded && !canaryDual.succeeded {
            checks.append(CheckItem(
                id: "canary_unreachable",
                category: "出口探测",
                title: "通用海外探测失败（网络或代理不通）",
                severity: .fail,
                detail: "无法连接 1.1.1.1/cdn-cgi/trace（\(canaryV4.error ?? "连接超时")），已熔断拦截，未向 claude.ai 发包",
                remediation: "请检查代理客户端节点是否可用，确认 TUN 或系统代理连接正常后再重试"
            ))
            let dev = procEnv.inspectDeviceConsistency(exitCountryCode: nil, exitExactTimezone: nil)
            return OpenGateReport(
                claudeInstalled: appInfo.installed,
                claudeVersion: appInfo.version,
                verdict: .noGo,
                transportMode: transport,
                proxySnapshot: proxySnap,
                routeSnapshot: routeSnap,
                proxyClients: proxyClients,
                canaryIPv4Trace: canaryV4,
                canaryIPv6Trace: canaryV6,
                canaryDomainTrace: canaryDual,
                deviceConsistency: dev,
                logScan: logScan,
                checks: checks,
                summaryHeadline: "网络或代理节点不通，禁止打开 Claude",
                summaryAdvice: "已安全拦截，全程未向 Claude 发送任何请求。请先检查代理节点连通性。"
            )
        }

        // Fail-Closed Check 2B: Any active IPv4 or Dual-Stack canary in restricted country
        let primaryCanary = canaryDual.succeeded ? canaryDual : canaryV4
        if let restricted = canaryV4.restrictedRegionName ?? canaryDual.restrictedRegionName {
            let leakIP = canaryV4.restrictedRegionName != nil ? (canaryV4.ip ?? "") : (canaryDual.ip ?? "")
            checks.append(CheckItem(
                id: "canary_restricted_region",
                category: "出口安全",
                title: "当前出口位于受限地区（\(restricted)）",
                severity: .fail,
                detail: "无害探测出口 IP \(leakIP) 归属 \(restricted)，已触发熔断保护，未触碰 claude.ai",
                remediation: Self.formatProxyClientHint(proxyClients)
            ))
            let dev = procEnv.inspectDeviceConsistency(exitCountryCode: primaryCanary.loc, exitExactTimezone: nil)
            return OpenGateReport(
                claudeInstalled: appInfo.installed,
                claudeVersion: appInfo.version,
                verdict: .noGo,
                transportMode: transport,
                proxySnapshot: proxySnap,
                routeSnapshot: routeSnap,
                proxyClients: proxyClients,
                canaryIPv4Trace: canaryV4,
                canaryIPv6Trace: canaryV6,
                canaryDomainTrace: canaryDual,
                deviceConsistency: dev,
                logScan: logScan,
                checks: checks,
                summaryHeadline: "当前为\(restricted)出口，严禁打开 Claude！",
                summaryAdvice: Self.formatProxyClientHint(proxyClients)
            )
        }

        // Fail-Closed Check 2C: IPv6 Direct Leak while IPv4 is proxied!
        if canaryV6.succeeded, let v6Restricted = canaryV6.restrictedRegionName {
            checks.append(CheckItem(
                id: "canary_ipv6_leak",
                category: "双栈防泄露",
                title: "捕获到致命 IPv6 直连抢跑泄露（\(v6Restricted)）",
                severity: .fail,
                detail: "IPv4 走了海外 (\(canaryV4.loc ?? "?"))，但 IPv6 出口 \(canaryV6.ip ?? "") 直连暴露在 \(v6Restricted)！Chromium Happy Eyeballs 极易走该路径导致封号",
                remediation: "请立即在代理客户端中禁用 IPv6 / 开启 TUN IPv6 严格路由，或在系统网络设置中将配置 IPv6 改为「仅本地链接」"
            ))
            let dev = procEnv.inspectDeviceConsistency(exitCountryCode: canaryV6.loc, exitExactTimezone: nil)
            return OpenGateReport(
                claudeInstalled: appInfo.installed,
                claudeVersion: appInfo.version,
                verdict: .noGo,
                transportMode: transport,
                proxySnapshot: proxySnap,
                routeSnapshot: routeSnap,
                proxyClients: proxyClients,
                canaryIPv4Trace: canaryV4,
                canaryIPv6Trace: canaryV6,
                canaryDomainTrace: canaryDual,
                deviceConsistency: dev,
                logScan: logScan,
                checks: checks,
                summaryHeadline: "检测到 IPv6 直连泄露（\(v6Restricted)），已拦截启动！",
                summaryAdvice: "虽然 IPv4 走了代理，但本机原生 IPv6 绕过了代理直连回国。请先关闭 IPv6 或开启 TUN IPv6 接管。"
            )
        }

        checks.append(CheckItem(
            id: "canary_safe",
            category: "出口安全",
            title: "通用双栈出口安全校验通过",
            severity: .pass,
            detail: "Cloudflare 出口 \(primaryCanary.ip ?? "-") (\(primaryCanary.loc ?? "-"), \(primaryCanary.latencyMs)ms)" + (canaryV6.succeeded ? " · IPv6 \(canaryV6.loc ?? "-")" : " · IPv6 已隔离")
        ))

        // Step 3: Safe to probe claude.ai & anthropic.com (Credential-free trace)
        onStep?("通用出口安全，正在校验 Claude / Anthropic 全域名分流路径...")
        async let claudeTraceTask = prober.probeTrace(label: "Claude.ai", urlString: "https://claude.ai/cdn-cgi/trace", timeout: timeout)
        async let anthropicTraceTask = prober.probeTrace(label: "Anthropic.com", urlString: "https://www.anthropic.com/cdn-cgi/trace", timeout: timeout)
        let (claudeTrace, anthropicTrace) = await (claudeTraceTask, anthropicTraceTask)

        if !claudeTrace.succeeded {
            checks.append(CheckItem(
                id: "claude_trace_failed",
                category: "Claude 可用性",
                title: "无法连接 claude.ai",
                severity: .fail,
                detail: "通用出口正常，但 claude.ai 访问失败（\(claudeTrace.error ?? "超时")）",
                remediation: "当前代理节点可能被 Cloudflare/Claude 阻断或分流规则有误，请切换节点重试"
            ))
        } else if let claudeRestricted = claudeTrace.restrictedRegionName {
            checks.append(CheckItem(
                id: "claude_split_leak",
                category: "分流完整性",
                title: "claude.ai 分流漏网走入受限地区（\(claudeRestricted)）",
                severity: .fail,
                detail: "通用出口为 \(primaryCanary.loc ?? "-")，但 claude.ai 出口为 \(claudeTrace.ip ?? "-") (\(claudeRestricted))",
                remediation: "请在代理分流规则中将 claude.ai、anthropic.com、AS399358 加入代理组或切换至全局/TUN 模式"
            ))
        } else {
            checks.append(CheckItem(
                id: "claude_exit_region",
                category: "出口安全",
                title: "Claude 出口地区受支持",
                severity: .pass,
                detail: "claude.ai 出口 \(claudeTrace.ip ?? "-")（地区 \(claudeTrace.loc ?? "-")，延迟 \(claudeTrace.latencyMs)ms）"
            ))
        }

        if claudeTrace.isIPv6 {
            checks.append(CheckItem(
                id: "claude_ipv6_exit_warn",
                category: "双栈防泄露",
                title: "当前通过 IPv6 出口访问 Claude",
                severity: .warning,
                detail: "出口为 IPv6 地址 \(claudeTrace.ip ?? "")，部分机房 IPv6 段风控评分不稳定",
                remediation: "建议优先使用纯净的 IPv4 出口访问 Claude Desktop 与 Claude Code"
            ))
        }

        if let anthRestricted = anthropicTrace.restrictedRegionName {
            checks.append(CheckItem(
                id: "anthropic_split_leak",
                category: "分流完整性",
                title: "anthropic.com 分流漏网走入受限地区（\(anthRestricted)）",
                severity: .fail,
                detail: "anthropic.com 出口位于 \(anthRestricted) (\(anthropicTrace.ip ?? "-"))，API 请求会直连暴露",
                remediation: "请将 DOMAIN-SUFFIX,anthropic.com 与 IP-CIDR,160.79.104.0/21 加入代理规则"
            ))
        } else if anthropicTrace.succeeded, let cLoc = claudeTrace.loc, let aLoc = anthropicTrace.loc, cLoc != aLoc {
            checks.append(CheckItem(
                id: "anthropic_loc_mismatch",
                category: "分流完整性",
                title: "claude.ai 与 anthropic.com 出口国家不一致",
                severity: .warning,
                detail: "claude.ai 为 \(cLoc)，而 anthropic.com 为 \(aLoc)",
                remediation: "建议让所有 Claude/Anthropic 域名走同一个固定代理节点"
            ))
        }

        // Step 4: Risk Purity, Rotation Sampling & UDP STUN Leak Check (plus Deep checks if requested)
        let claudeIP = claudeTrace.ip
        onStep?(deep ? "正在执行深度体检（IP 纯净度 / 轮换 / DNS 泄露 / UDP STUN / 中国出口对比）..." : "正在查询出口 IP 纯净度评分、轮换稳定性与 UDP 通道...")

        async let riskTask: IPRiskSnapshot? = claudeIP != nil ? prober.fetchIPRisk(ip: claudeIP!, timeout: timeout + 3.0) : nil
        async let claudeGeoTask: GeoIPSummary? = claudeIP != nil ? prober.fetchGeoIP(ip: claudeIP!, timeout: timeout) : nil
        async let cfGeoTask: GeoIPSummary? = primaryCanary.ip != nil ? prober.fetchGeoIP(ip: primaryCanary.ip!, timeout: timeout) : nil
        async let rotationTask: [String] = (claudeTrace.succeeded && sampleCount > 1)
            ? prober.sampleExitRotation(urlString: "https://claude.ai/cdn-cgi/trace", sampleCount: sampleCount, timeout: timeout)
            : (claudeIP.map { [$0] } ?? [])
        async let udpTask: UDPLeakResult = prober.detectUDPLeak(claudeExitIP: claudeIP, timeout: min(timeout, 3.2))

        // Deep-only tasks
        async let cnIPTask: String? = deep ? prober.fetchCNExitIP(timeout: 4.5) : nil
        async let dnsTask: DNSLeakResult = deep ? prober.detectDNSLeak(claudeCountryCode: claudeTrace.loc, timeout: 5.0) : DNSLeakResult()
        async let statusTask: String? = deep ? prober.fetchClaudeServiceStatus(timeout: 3.5) : nil

        let (ipRisk, claudeGeo, cfGeo, rotationIPs, udpLeak, cnIP, dnsLeak, serviceStatus) = await (
            riskTask, claudeGeoTask, cfGeoTask, rotationTask, udpTask, cnIPTask, dnsTask, statusTask
        )

        var cnGeo: GeoIPSummary?
        if let cnIP {
            cnGeo = await prober.fetchGeoIP(ip: cnIP, timeout: 3.5)
        }

        // Evaluate IP Risk & Trust Score
        if let risk = ipRisk {
            if let cc = risk.countryCode?.uppercased(), let restrictedName = RestrictedRegions.restrictedCountryNames[cc] {
                checks.append(CheckItem(
                    id: "iprisk_restricted",
                    category: "IP 纯净度",
                    title: "IP 情报库判定出口位于受限地区（\(restrictedName)）",
                    severity: .fail,
                    detail: "IP \(risk.ip) 归属地为 \(restrictedName)",
                    remediation: "请更换至美国、日本、新加坡、英国等支持地区的节点"
                ))
            } else if risk.isTor == true {
                checks.append(CheckItem(
                    id: "iprisk_tor",
                    category: "IP 纯净度",
                    title: "出口被标记为 Tor 匿名节点",
                    severity: .fail,
                    detail: "Claude 对 Tor 出口严格封禁",
                    remediation: "请切换为普通住宅或优质专线代理节点"
                ))
            } else if let score = risk.trustScore {
                if score < 25 {
                    checks.append(CheckItem(
                        id: "iprisk_score_low",
                        category: "IP 纯净度",
                        title: "Trust Score 过低（\(score)/100 · 高危可疑）",
                        severity: .fail,
                        detail: "\(risk.ipTypeLabel) · \(risk.asOrganization ?? "未知 ASN")，极易触发人机验证或账号封禁",
                        remediation: "请切换至 Trust Score ≥ 50（推荐 ≥ 70）的节点"
                    ))
                } else if score < 50 {
                    checks.append(CheckItem(
                        id: "iprisk_score_warn",
                        category: "IP 纯净度",
                        title: "Trust Score 偏低（\(score)/100 · 中性风险）",
                        severity: .warning,
                        detail: "\(risk.ipTypeLabel) · \(risk.asOrganization ?? "未知运营商")",
                        remediation: "建议切换至评分 ≥ 70 的纯净节点以降低长期风控概率"
                    ))
                } else {
                    checks.append(CheckItem(
                        id: "iprisk_score_ok",
                        category: "IP 纯净度",
                        title: "Trust Score 评分 \(score)/100（\(risk.purityLabel)）",
                        severity: .pass,
                        detail: "\(risk.ipTypeLabel) · AS\(risk.asn.map(String.init) ?? "?") \(risk.asOrganization ?? "")"
                    ))
                }
            }

            if risk.isDatacenter == true || risk.isResidential == false {
                checks.append(CheckItem(
                    id: "iprisk_datacenter",
                    category: "IP 属性",
                    title: "当前出口为机房 IP (Hosting)",
                    severity: .warning,
                    detail: "机房 IP 可正常使用，但相比家庭住宅 ISP 更容易出现偶发验证码",
                    remediation: "条件允许时可优先选择住宅/ISP 属性节点"
                ))
            }
        } else if claudeTrace.succeeded {
            checks.append(CheckItem(
                id: "iprisk_degraded",
                category: "IP 纯净度",
                title: "IP 风险情报源响应超时（已降级使用本地与 Cloudflare 判定）",
                severity: .info,
                detail: "不影响核心地区门禁判定"
            ))
        }

        // Evaluate Exit Rotation
        var mergedRotation = rotationIPs
        if let cip = claudeIP, !mergedRotation.contains(cip) {
            mergedRotation.insert(cip, at: 0)
        }
        if mergedRotation.count > 1 {
            checks.append(CheckItem(
                id: "exit_rotation",
                category: "稳定性",
                title: "检测到机场侧出口 IP 轮换（\(mergedRotation.count) 个不同 IP）",
                severity: .warning,
                detail: "\(sampleCount) 次独立连接出现多个出口：\(mergedRotation.joined(separator: ", "))",
                remediation: "高频变动 IP 容易引起 Claude 异常登录风控，请避免使用负载均衡组，改为手动固定单一节点"
            ))
        } else if sampleCount > 1 && mergedRotation.count == 1 {
            checks.append(CheckItem(
                id: "exit_rotation_ok",
                category: "稳定性",
                title: "出口 IP 固定无轮换",
                severity: .pass,
                detail: "\(sampleCount) 次独立 TCP 会话采样保持同一出口 IP"
            ))
        }

        // Evaluate UDP / QUIC STUN Leak
        if udpLeak.checked {
            if !udpLeak.matchesClaudeExit, let lip = udpLeak.leakedIP {
                let leakedCC = udpLeak.leakedGeo?.countryCode?.uppercased() ?? ""
                if let restrictedUDP = RestrictedRegions.restrictedCountryNames[leakedCC] {
                    checks.append(CheckItem(
                        id: "udp_leak_critical",
                        category: "UDP / QUIC 防泄露",
                        title: "UDP 通道直连暴露了受限地区 IP（\(restrictedUDP)）",
                        severity: .fail,
                        detail: "STUN 测得公网 UDP 出口为 \(lip) (\(restrictedUDP))，Electron 的 HTTP/3 (QUIC) 或 WebRTC 会泄漏真实位置！",
                        remediation: "请开启 TUN 模式（并启用 UDP 转发），或在代理客户端中接管/阻断直连 UDP 443"
                    ))
                } else {
                    checks.append(CheckItem(
                        id: "udp_leak_mismatch",
                        category: "UDP / QUIC 防泄露",
                        title: "UDP 出口与 Claude TCP 出口不一致",
                        severity: .warning,
                        detail: "UDP 出口为 \(lip) (\(udpLeak.leakedGeo?.country ?? "海外"))，不同于 Claude 出口 \(claudeIP ?? "-")",
                        remediation: "建议确保代理节点的 TCP 与 UDP 走同一出口"
                    ))
                }
            } else if udpLeak.publicUDPIPs.isEmpty {
                checks.append(CheckItem(
                    id: "udp_leak_unknown",
                    category: "UDP / QUIC 防泄露",
                    title: "未获取到 UDP 公网映射（无法确认）",
                    severity: .info,
                    detail: "UDP 可能已被隔离，或 STUN 探测失败；该项为 best-effort，建议手动确认代理已接管 UDP。"
                ))
            } else {
                checks.append(CheckItem(
                    id: "udp_leak_ok",
                    category: "UDP / QUIC 防泄露",
                    title: "UDP / WebRTC 通道无泄露",
                    severity: .pass,
                    detail: "UDP 出口 (\(udpLeak.publicUDPIPs.first!)) 与代理出口一致"
                ))
            }
        }

        // Evaluate Deep DNS Leak
        if dnsLeak.checked {
            if dnsLeak.hasCNLeak {
                checks.append(CheckItem(
                    id: "dns_leak_cn",
                    category: "DNS 安全",
                    title: "检测到中国大陆 DNS 解析器泄露",
                    severity: .warning,
                    detail: "DNS 出口包含 \(dnsLeak.primaryResolverGeo?.ip ?? "") (\(dnsLeak.primaryResolverGeo?.isp ?? "CN DNS"))",
                    remediation: "建议在代理客户端中开启 Fake-IP 或远程加密 DoH 解析"
                ))
            } else if dnsLeak.resolverIPs.isEmpty {
                checks.append(CheckItem(
                    id: "dns_leak_unknown",
                    category: "DNS 安全",
                    title: "未获取到 DNS 解析器信息（无法确认）",
                    severity: .info,
                    detail: "可能已加密 / 由远端代理解析，也可能探测失败；该项为 best-effort。"
                ))
            } else {
                checks.append(CheckItem(
                    id: "dns_leak_ok",
                    category: "DNS 安全",
                    title: "未检测到中国大陆 DNS 泄露",
                    severity: .pass,
                    detail: "DNS 解析出口位于海外 (\(dnsLeak.primaryResolverGeo?.countryCode ?? "-"))"
                ))
            }
        }

        // Device Timezone & Language Consistency
        let effectiveCC = ipRisk?.countryCode ?? claudeTrace.loc
        let devConsistency = procEnv.inspectDeviceConsistency(
            exitCountryCode: effectiveCC,
            exitExactTimezone: ipRisk?.timezone
        )
        if devConsistency.isChinaMainlandTimezone {
            checks.append(CheckItem(
                id: "tz_cn_warn",
                category: "环境指纹",
                title: "系统时区为中国大陆时区 (\(devConsistency.localTimezone))",
                severity: .warning,
                detail: "Claude Code 与网页端会校验系统时区与代理出口 (\(devConsistency.exitTimezone ?? "海外")) 是否匹配",
                remediation: "高敏账号建议在系统设置中临时将时区调整为与代理一致的时区（如 America/Los_Angeles）"
            ))
        } else if devConsistency.timezoneMatched == false {
            checks.append(CheckItem(
                id: "tz_mismatch",
                category: "环境指纹",
                title: "本地时区与代理出口时区存在偏差",
                severity: .info,
                detail: "本地 \(devConsistency.localTimezone)，出口对应 \(devConsistency.exitTimezone ?? "未知")"
            ))
        } else if devConsistency.timezoneMatched == true {
            checks.append(CheckItem(
                id: "tz_match_ok",
                category: "环境指纹",
                title: "系统时区与代理出口时区一致",
                severity: .pass,
                detail: "\(devConsistency.localTimezone)"
            ))
        }

        if devConsistency.languageMatched == false {
            checks.append(CheckItem(
                id: "lang_mismatch",
                category: "环境指纹",
                title: "系统首选语言 (\(devConsistency.primaryLanguageCode)) 与出口常用语言不同",
                severity: .info,
                detail: "当前首选语言列表：\(devConsistency.appleLanguages.joined(separator: ", "))（仅作提示，不阻塞使用）"
            ))
        }

        // Recent Log Incident History
        if logScan.recentRegionUnavailableCount > 0 || logScan.recentAuth403Count > 0 {
            checks.append(CheckItem(
                id: "log_recent_403",
                category: "历史日志",
                title: "Claude 本地日志存在近期被拒记录",
                severity: .warning,
                detail: "扫描到 region_unavailable \(logScan.recentRegionUnavailableCount) 次、遥测/接口 403 \(logScan.recentAuth403Count) 次",
                remediation: "请务必坚持「先通过本软件检测开 Claude → 用完点本软件安全退出 → 看到绿灯后再关代理」"
            ))
        }

        // Final Verdict Aggregation
        let hasFail = checks.contains(where: { $0.severity == .fail })
        let hasWarn = checks.contains(where: { $0.severity == .warning })
        let finalVerdict: VerdictLevel = hasFail ? .noGo : (hasWarn ? .goWithWarnings : .go)

        // Save local-only IP history if we got a valid Claude exit IP
        if let cip = claudeIP {
            let locText = claudeGeo?.formattedLocation.isEmpty == false
                ? claudeGeo!.formattedLocation
                : (ipRisk?.country ?? claudeTrace.loc ?? "未知")
            historyStore.record(IPHistoryEntry(
                ip: cip,
                countryCode: effectiveCC,
                location: locText,
                asnOrg: ipRisk?.asOrganization,
                trustScore: ipRisk?.trustScore,
                isResidential: ipRisk?.isResidential
            ))
        }

        let headline: String
        let advice: String
        switch finalVerdict {
        case .go:
            headline = "出口环境纯净安全，可以放心打开 Claude Desktop"
            advice = "Claude 出口位于 \(effectiveCC ?? "支持地区") (\(claudeIP ?? ""))，双栈无泄露，分流一致。"
        case .goWithWarnings:
            headline = "出口地区安全，可打开 Claude（附带优化建议）"
            let warnCount = checks.filter { $0.severity == .warning }.count
            advice = "核心安全门禁已通过，存在 \(warnCount) 项非阻断提醒（如机房属性/轮换/时区），可按需优化。"
        case .noGo, .frozenEmergency:
            let firstFail = checks.first(where: { $0.severity == .fail })
            headline = firstFail?.title ?? "安全门禁未通过，请勿打开 Claude"
            advice = firstFail?.remediation ?? Self.formatProxyClientHint(proxyClients)
        }

        return OpenGateReport(
            claudeInstalled: appInfo.installed,
            claudeVersion: appInfo.version,
            verdict: finalVerdict,
            transportMode: transport,
            proxySnapshot: proxySnap,
            routeSnapshot: routeSnap,
            proxyClients: proxyClients,
            canaryIPv4Trace: canaryV4,
            canaryIPv6Trace: canaryV6,
            canaryDomainTrace: canaryDual,
            claudeTrace: claudeTrace,
            anthropicTrace: anthropicTrace,
            cnExitIP: cnIP,
            cnExitGeo: cnGeo,
            cfExitGeo: cfGeo,
            claudeExitGeo: claudeGeo,
            ipRisk: ipRisk,
            rotationUniqueIPs: mergedRotation,
            rotationSampleCount: sampleCount,
            dnsLeak: dnsLeak,
            udpLeak: udpLeak,
            claudeServiceIndicator: serviceStatus,
            deviceConsistency: devConsistency,
            logScan: logScan,
            checks: checks,
            summaryHeadline: headline,
            summaryAdvice: advice
        )
    }

    // MARK: - Close Gate Evaluation (Safe to Turn Off Proxy?)

    public func evaluateCloseGate() -> CloseGateReport {
        let processScanAvailable = procEnv.isProcessScanAvailable()
        let processes = procEnv.scanClaudeProcesses()
        let claudePIDSet = Set(processes.map(\.pid))
        let (claudeSockets, browserSockets) = procEnv.scanActiveSockets(claudePIDs: claudePIDSet)
        let logScan = procEnv.inspectClaudeLogs()
        let proxyClients = netEnv.scanInstalledProxyClients()

        var checks: [CheckItem] = []

        if !processScanAvailable {
            checks.append(CheckItem(
                id: "process_scan_failed",
                category: "进程检测",
                title: "无法读取系统进程列表",
                severity: .fail,
                detail: "ps 执行失败或超时，无法确认 Claude 家族进程是否已退出；按不安全处理。",
                remediation: "请检查 /bin/ps 是否可执行、是否有安全软件拦截，然后重新检测。"
            ))
        }

        let stoppedProcs = processes.filter(\.isStopped)
        let runningProcs = processes.filter { !$0.isStopped }

        if !stoppedProcs.isEmpty {
            let names = stoppedProcs.map { "\($0.kind.rawValue) (PID \($0.pid))" }.joined(separator: "、")
            checks.append(CheckItem(
                id: "frozen_processes",
                category: "断路器冻结",
                title: "存在已被断路器紧急冻结的 Claude 进程",
                severity: .fail,
                detail: names,
                remediation: "请先恢复代理后解冻退出，或点击「零发包强制关闭」彻底清理进程后再关代理"
            ))
        }

        if !runningProcs.isEmpty {
            let grouped = Dictionary(grouping: runningProcs, by: \.kind)
                .map { "\($0.key.rawValue) ×\($0.value.count)" }
                .sorted()
                .joined(separator: "、")
            checks.append(CheckItem(
                id: "active_claude_processes",
                category: "进程检测",
                title: "检测到正在运行的 Claude 关联进程（共 \(runningProcs.count) 个）",
                severity: .fail,
                detail: grouped,
                remediation: "现在关闭代理会导致带凭据请求直连暴露！请先点击「安全关闭 Claude」"
            ))
        } else if stoppedProcs.isEmpty && processScanAvailable {
            checks.append(CheckItem(
                id: "no_claude_processes",
                category: "进程检测",
                title: "没有任何 Claude Desktop / CLI / ShipIt 进程运行",
                severity: .pass,
                detail: "已核验主进程、Helper、ShipIt 更新器、Chrome 宿主与 Claude Code CLI 全清零"
            ))
        }

        if !claudeSockets.isEmpty {
            checks.append(CheckItem(
                id: "active_claude_sockets",
                category: "网络排空",
                title: "仍有 \(claudeSockets.count) 条未排空的 Claude 网络连接",
                severity: .fail,
                detail: claudeSockets.prefix(3).map { "\($0.processName)[\($0.pid)] \($0.remoteEndpoint) (\($0.state))" }.joined(separator: "；"),
                remediation: "请等待连接排空（通常 1~3 秒）后再关闭代理"
            ))
        } else {
            checks.append(CheckItem(
                id: "sockets_drained",
                category: "网络排空",
                title: "Claude 关联外部网络套接字已全部归零",
                severity: .pass,
                detail: "内核无残留活动连接"
            ))
        }

        if processes.isEmpty && !logScan.isQuietFor2Seconds {
            let ago = String(format: "%.1f", logScan.secondsSinceLastWrite ?? 0)
            checks.append(CheckItem(
                id: "log_not_quiet_yet",
                category: "退出收尾",
                title: "main.log 刚刚仍有写入（\(ago) 秒前）",
                severity: .fail,
                detail: "正在等待退出清理完全静默（需连续静默 ≥ 2.0 秒）",
                remediation: "请稍候 2 秒再关闭代理"
            ))
        } else if logScan.mainLogExists {
            let markerNote = logScan.lastQuitMarker.map { " · 最后退出标记：\($0)" } ?? ""
            checks.append(CheckItem(
                id: "log_quiet_ok",
                category: "退出收尾",
                title: "Claude 日志已完全静默",
                severity: .pass,
                detail: "距上次日志写入已超过 2 秒\(markerNote)"
            ))
        }

        if !browserSockets.isEmpty {
            checks.append(CheckItem(
                id: "browser_anthropic_sockets",
                category: "浏览器提醒",
                title: "检测到浏览器仍有连接至 Anthropic 网段（\(browserSockets.count) 条）",
                severity: .warning,
                detail: browserSockets.prefix(2).map { "\($0.processName) -> \($0.remoteEndpoint)" }.joined(separator: "；"),
                remediation: "关代理前请确认 Chrome / Safari 中已关闭 claude.ai 网页标签页，避免网页 Cookie 直连"
            ))
        }

        let status: ProxyCloseStatus
        let headline: String
        let advice: String

        if !stoppedProcs.isEmpty {
            status = .frozenNeedsAction
            headline = "Claude 正处于紧急冻结态，请处置后再关闭代理"
            advice = "进程已被挂起不会发包，但尚未退出。请点击「零发包强制关闭」清理完毕后再关代理。"
        } else if !processScanAvailable {
            status = .doNotCloseProxy
            headline = "⛔️ 无法读取进程列表，无法确认 Claude 已退出"
            advice = "为避免误报安全，请先排除系统权限或安全软件对 /bin/ps 的拦截，再重新检测。"
        } else if !runningProcs.isEmpty || !claudeSockets.isEmpty || !logScan.isQuietFor2Seconds {
            status = .doNotCloseProxy
            headline = "⛔️ 现在不要关闭代理！Claude 尚未完全退出"
            advice = "请点击「安全关闭 Claude」按钮，等待所有后台进程与网络连接排空后再关闭代理客户端。"
        } else {
            status = .safeToCloseProxy
            headline = "✅ 现在可以安全关闭代理！"
            advice = browserSockets.isEmpty
                ? "所有 Claude Desktop、辅助进程、更新器与终端 CLI 均已彻底退出且网络排空，关闭代理不会产生任何直连请求。"
                : "Claude 客户端与 CLI 已彻底退出；但检测到浏览器仍有 Anthropic 连接，建议顺手关闭 claude.ai 网页标签后再关代理。"
        }

        return CloseGateReport(
            status: status,
            processes: processes,
            claudeSockets: claudeSockets,
            browserAnthropicSockets: browserSockets,
            logScan: logScan,
            proxyClients: proxyClients,
            checks: checks,
            summaryHeadline: headline,
            summaryAdvice: advice
        )
    }

    private static func formatProxyClientHint(_ clients: [ProxyClientApp]) -> String {
        if clients.isEmpty {
            return "请先开启代理客户端（确保开启 TUN 模式或系统代理并选择美/日/新等支持地区节点）后再打开 Claude。"
        }
        let names = clients.map { $0.isRunning ? "\($0.name)（运行中，请检查节点/TUN开关）" : "\($0.name)（未启动）" }.joined(separator: "、")
        return "本机检测到代理客户端：\(names)。请先开启海外支持节点后再启动 Claude。"
    }
}
