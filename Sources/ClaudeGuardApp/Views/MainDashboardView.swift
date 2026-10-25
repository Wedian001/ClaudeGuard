import SwiftUI
import AppKit
import ClaudeGuardCore

public struct MainDashboardView: View {
    @Bindable var controller: ClaudeLifecycleController

    enum InspectorTab: Int, CaseIterable, Identifiable {
        case evidence = 0
        case processes = 1
        case history = 2
        var id: Int { rawValue }
        var title: String {
            switch self {
            case .evidence: return "诊断证据清单"
            case .processes: return "全家桶进程与连接"
            case .history: return "出口 IP 历史"
            }
        }
    }

    public init(controller: ClaudeLifecycleController) {
        self.controller = controller
    }

    public var body: some View {
        GlassEffectContainer {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    // 1. Top Workflow Closed-Loop Deck
                    closedLoopHeroSection

                    // 2. Three-Exit Split-Tunnel Hero Cards (China / Cloudflare / Claude)
                    threeExitComparisonSection

                    // 3. Purity Score + Security Flags + Leak & Fingerprint Matrix
                    purityAndSecurityMatrixSection

                    // 4. Bottom Tabbed Inspector
                    bottomInspectorSection
                }
                .padding(22)
            }
        }
        .frame(minWidth: 940, minHeight: 680)
        .toolbar {
            ToolbarItemGroup(placement: .automatic) {
                Button {
                    Task { await controller.runOpenCheck(deep: false) }
                } label: {
                    Label("快速检测", systemImage: "bolt.horizontal.circle")
                }
                .buttonStyle(.glass)
                .disabled(controller.isBusy)

                Button {
                    Task { await controller.runOpenCheck(deep: true) }
                } label: {
                    Label("深度全量体检", systemImage: "stethoscope")
                }
                .buttonStyle(.glassProminent)
                .tint(.indigo)
                .disabled(controller.isBusy)

                Toggle(isOn: $controller.maskIPInUI) {
                    Label("隐藏 IP", systemImage: controller.maskIPInUI ? "eye.slash.fill" : "eye")
                }
                .toggleStyle(.button)
                .buttonStyle(.glass)

                Toggle(isOn: $controller.activeProtectionEnabled) {
                    Label("主动断路器", systemImage: "bolt.shield.fill")
                }
                .toggleStyle(.switch)

                Toggle("开机自启", isOn: Binding(
                    get: { controller.isLaunchAtLoginEnabled },
                    set: { newVal in
                        try? controller.setLaunchAtLogin(newVal)
                    }
                ))
                .toggleStyle(.switch)
            }
        }
        .onAppear {
            controller.refreshFastLocalState()
        }
    }

    // MARK: - Section 1: Closed-Loop Control Deck

    private var closedLoopHeroSection: some View {
        VStack(spacing: 14) {
            // Special Top Alert Banner when Proxy-Off Ready or Emergency Frozen or Draining
            if case .safeToTurnOffProxy(let confirmedAt) = controller.stage {
                LiquidGlassCard(tint: .green, cornerRadius: 20, padding: 18) {
                    HStack(spacing: 14) {
                        Image(systemName: "checkmark.seal.fill")
                            .font(.system(size: 38))
                            .foregroundStyle(.green)

                        VStack(alignment: .leading, spacing: 4) {
                            Text("✅ Claude 已完全退出并排空所有连接，现在可以安全关闭代理！")
                                .font(.title3.weight(.bold))
                                .foregroundStyle(.green)
                            Text("核验时间：\(confirmedAt.formatted(date: .omitted, time: .standard)) · 主进程、Helper、ShipIt 更新器、Claude Code CLI 与外部 Socket 均已归零，日志已静默 ≥ 2 秒。")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                }
            } else if case let .emergencyFrozen(reason, count) = controller.stage {
                LiquidGlassCard(tint: .cyan, cornerRadius: 20, padding: 18) {
                    HStack(spacing: 14) {
                        Image(systemName: "snowflake.circle.fill")
                            .font(.system(size: 38))
                            .foregroundStyle(.cyan)

                        VStack(alignment: .leading, spacing: 4) {
                            Text("❄️ 主动断路器已紧急冻结 \(count) 个 Claude 进程（零直连发包）")
                                .font(.title3.weight(.bold))
                                .foregroundStyle(.cyan)
                            Text(reason)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        HStack(spacing: 10) {
                            Button("零发包强退") {
                                Task { await controller.emergencyForceCloseFrozenClaude() }
                            }
                            .buttonStyle(.glass)
                            .controlSize(.large)

                            Button("已恢复代理 · 解冻继续") {
                                Task { _ = await controller.verifyProxyAndResumeFrozenClaude() }
                            }
                            .buttonStyle(.glassProminent)
                            .tint(.cyan)
                            .controlSize(.large)
                        }
                    }
                }
            }

            HStack(alignment: .top, spacing: 16) {
                // Gate 1: Safe Open Claude Card
                LiquidGlassCard(tint: openTone.color, cornerRadius: 20, padding: 18) {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Label("门禁一：现在能否安全打开 Claude？", systemImage: "door.left.hand.open")
                                .font(.headline)
                            Spacer()
                            StatusBadgePill(
                                text: controller.openReport?.verdict.titleText ?? "正在检测...",
                                tone: openTone
                            )
                        }

                        Text(controller.openReport?.summaryHeadline ?? "正在校验双栈出口与分流完整性...")
                            .font(.title3.weight(.bold))

                        Text(controller.openReport?.summaryAdvice ?? "软件遵循严格零泄露探测顺序：先探 1.1.1.1 双栈出口，确认安全后才校验 Claude 域名。")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)

                        HStack(spacing: 10) {
                            let isClaudeActive = !(controller.closeReport?.processes.isEmpty ?? true)
                            Button {
                                Task { _ = await controller.checkAndOpenClaude() }
                            } label: {
                                Label(
                                    isClaudeActive ? "Claude 正在运行（重新校验并置顶）" : "安全检测并打开 Claude Desktop",
                                    systemImage: "paperplane.fill"
                                )
                                .font(.callout.weight(.semibold))
                                .padding(.horizontal, 6)
                            }
                            .buttonStyle(.glassProminent)
                            .tint(openTone == .danger ? .blue : .green)
                            .controlSize(.large)
                            .disabled(controller.isBusy)

                            if let clients = controller.openReport?.proxyClients, !clients.isEmpty {
                                Menu {
                                    ForEach(clients) { client in
                                        Button("打开 \(client.name)\(client.isRunning ? " (运行中)" : "")") {
                                            controller.openProxyClient(client)
                                        }
                                    }
                                } label: {
                                    Label("代理客户端", systemImage: "network")
                                }
                                .menuStyle(.button)
                                .buttonStyle(.glass)
                                .controlSize(.large)
                            }
                        }

                        if case let .checkingOpenGate(step) = controller.stage {
                            HStack(spacing: 8) {
                                ProgressView().controlSize(.small)
                                Text(step).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }

                // Gate 2: Safe Quit Claude & Turn Off Proxy Card
                LiquidGlassCard(tint: closeTone.color, cornerRadius: 20, padding: 18) {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Label("门禁二：现在能否安全关闭代理？", systemImage: "power.dotted")
                                .font(.headline)
                            Spacer()
                            StatusBadgePill(
                                text: closeStatusLabel,
                                tone: closeTone
                            )
                        }

                        Text(controller.closeReport?.summaryHeadline ?? "正在扫描 Claude 全家桶进程与连接...")
                            .font(.title3.weight(.bold))

                        Text(controller.closeReport?.summaryAdvice ?? "只有当全部主进程、Helper、ShipIt 更新器与 Claude Code CLI 彻底退出且网络排空后才可关闭代理。")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)

                        HStack(spacing: 10) {
                            let procCount = controller.closeReport?.processes.count ?? 0
                            Button {
                                Task { _ = await controller.safeQuitClaudeAndVerifyDrain() }
                            } label: {
                                Label(
                                    procCount > 0 ? "安全退出 Claude（排空后提示关代理）" : "立即复核关代理安全性",
                                    systemImage: procCount > 0 ? "stop.circle.fill" : "checkmark.shield.fill"
                                )
                                .font(.callout.weight(.semibold))
                                .padding(.horizontal, 6)
                            }
                            .buttonStyle(.glassProminent)
                            .tint(procCount > 0 ? .orange : .teal)
                            .controlSize(.large)
                            .disabled(controller.isBusy)

                            Button {
                                controller.refreshLocalCloseGate()
                            } label: {
                                Label("刷新进程", systemImage: "arrow.triangle.2.circlepath")
                            }
                            .buttonStyle(.glass)
                            .controlSize(.large)
                        }

                        if case let .quittingDraining(step, _, elapsed) = controller.stage {
                            HStack(spacing: 8) {
                                ProgressView().controlSize(.small)
                                Text("[\(elapsed)s] \(step)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: - Section 2: Three-Exit Comparison Cards

    private var threeExitComparisonSection: some View {
        HStack(spacing: 14) {
            exitHeroCard(
                title: "🇨🇳 中国大陆出口 IPv4",
                ip: controller.openReport?.cnExitIP,
                countryCode: "CN",
                subtitle: controller.openReport?.cnExitGeo?.formattedLocation ?? "点上方「深度全量体检」探测国内分流出口",
                badge: controller.openReport?.cnExitIP != nil ? ("国内分流", .neutral) : ("按需探测", .neutral)
            )

            let cfTrace = controller.openReport?.canaryDomainTrace ?? controller.openReport?.canaryIPv4Trace
            exitHeroCard(
                title: "☁️ Cloudflare 通用双栈出口",
                ip: cfTrace?.ip,
                countryCode: cfTrace?.loc,
                subtitle: controller.openReport?.cfExitGeo?.formattedLocation ?? (cfTrace.map { "\($0.loc ?? "-") · \($0.colo ?? "") · \($0.latencyMs)ms" } ?? "等待探测"),
                badge: cfTrace?.succeeded == true
                    ? (cfTrace?.restrictedRegionName == nil ? ("海外正常", .safe) : ("受限地区", .danger))
                    : ("未连接", .neutral)
            )

            let claudeTrace = controller.openReport?.claudeTrace
            exitHeroCard(
                title: "🤖 Claude AI 真实出口",
                ip: claudeTrace?.ip,
                countryCode: claudeTrace?.loc,
                subtitle: controller.openReport?.claudeExitGeo?.formattedLocation ?? (claudeTrace.map { "\($0.loc ?? "-") · \($0.colo ?? "") · \($0.latencyMs)ms" } ?? "确认通用出口安全后自动探测"),
                badge: claudeTrace?.succeeded == true
                    ? (claudeTrace?.restrictedRegionName == nil ? ("支持地区", .safe) : ("直连风险", .danger))
                    : ("已隔离/待检", .neutral)
            )
        }
    }

    private func exitHeroCard(
        title: String,
        ip: String?,
        countryCode: String?,
        subtitle: String,
        badge: (String, SemanticBadgeTone)
    ) -> some View {
        LiquidGlassCard(cornerRadius: 16, padding: 15) {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(title)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    Spacer()
                    StatusBadgePill(text: badge.0, tone: badge.1)
                }

                if let ip, !ip.isEmpty {
                    HStack(spacing: 6) {
                        Text(RestrictedRegions.flagEmoji(for: countryCode))
                            .font(.title3)
                        Text(RestrictedRegions.maskIPAddress(ip, enabled: controller.maskIPInUI))
                            .font(.system(.title3, design: .monospaced).weight(.bold))
                            .lineLimit(1)
                            .minimumScaleFactor(0.75)
                    }
                } else {
                    Text("—")
                        .font(.title2.weight(.semibold))
                        .foregroundStyle(.secondary)
                }

                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
    }

    // MARK: - Section 3: Purity Score, Security Detection & Leak Matrix

    private var purityAndSecurityMatrixSection: some View {
        let risk = controller.openReport?.ipRisk
        let isRestricted = controller.openReport?.claudeTrace?.restrictedRegionName != nil

        return HStack(alignment: .top, spacing: 14) {
            // Card A: Trust Score & IP Properties
            LiquidGlassCard(cornerRadius: 18, padding: 16) {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Claude 信任评分与 IP 属性")
                        .font(.headline)

                    TrustScoreGaugeView(
                        score: risk?.trustScore,
                        purityLabel: risk?.purityLabel ?? "待评估",
                        isRestricted: isRestricted
                    )

                    Divider().opacity(0.35)

                    MetricRow(
                        label: "IP 属性",
                        value: "",
                        badge: risk == nil
                            ? ("待检测", .neutral)
                            : (risk?.isResidential == true ? ("家庭住宅 IP", .safe) : ("机房 Hosting IP", .warning))
                    )
                    MetricRow(label: "国家 / 城市", value: [risk?.country, risk?.city].compactMap { $0 }.joined(separator: " · "))
                    MetricRow(label: "ASN 自治域", value: risk?.asn.map { "AS\($0)" } ?? "—")
                    MetricRow(label: "运营商", value: risk?.asOrganization ?? "—")
                }
            }

            // Card B: 5-Dimension Security & Rotation
            LiquidGlassCard(cornerRadius: 18, padding: 16) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("安全威胁与出口轮换")
                        .font(.headline)
                        .padding(.bottom, 4)

                    securityBoolRow("VPN 标记", flag: risk?.isVPN)
                    securityBoolRow("公开代理 (Proxy)", flag: risk?.isProxy)
                    securityBoolRow("Tor 匿名网", flag: risk?.isTor)
                    securityBoolRow("自动化爬虫 (Crawler)", flag: risk?.isCrawler)
                    securityBoolRow("历史滥用记录", flag: risk?.isAbuser)

                    Divider().opacity(0.35)

                    let rotCount = controller.openReport?.rotationUniqueIPs.count ?? 0
                    let sampleCount = controller.openReport?.rotationSampleCount ?? 0
                    MetricRow(
                        label: "独立连接出口轮换",
                        value: sampleCount > 0 ? "\(sampleCount) 次采样" : "",
                        badge: rotCount == 0
                            ? ("待采样", .neutral)
                            : (rotCount == 1 ? ("固定单一 IP", .safe) : ("\(rotCount) IP 轮换", .warning))
                    )
                }
            }

            // Card C: Leak & Device Fingerprint Matrix
            LiquidGlassCard(cornerRadius: 18, padding: 16) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("双栈防泄露与环境指纹")
                        .font(.headline)
                        .padding(.bottom, 4)

                    // Transport & TUN
                    MetricRow(
                        label: "传输接管模式",
                        value: "",
                        badge: (controller.openReport?.transportMode.rawValue ?? "未知", controller.openReport?.transportMode.isProtectedLocally == true ? .safe : .danger)
                    )

                    // IPv6 Leak
                    let v6Leak = controller.openReport?.canaryIPv6Trace?.restrictedRegionName != nil
                    let v6RouteRisk = controller.openReport?.routeSnapshot.hasIPv6DirectLeakRisk ?? false
                    MetricRow(
                        label: "IPv6 抢跑防泄露",
                        value: "",
                        badge: v6Leak ? ("直连泄露!", .danger) : (v6RouteRisk ? ("存在公网路由", .warning) : ("安全隔离", .safe))
                    )

                    // UDP / QUIC STUN
                    let udp = controller.openReport?.udpLeak
                    MetricRow(
                        label: "UDP / QUIC 通道",
                        value: "",
                        badge: udp?.checked == true
                            ? (udp?.matchesClaudeExit == true ? ("无泄露", .safe) : ("出口不一致", .warning))
                            : ("待检测", .neutral)
                    )

                    // DNS Leak
                    let dns = controller.openReport?.dnsLeak
                    MetricRow(
                        label: "DNS 泄露检测",
                        value: "",
                        badge: dns?.checked == true
                            ? (dns?.hasCNLeak == true ? ("含中国 DNS", .warning) : ("未检测到泄露", .safe))
                            : ("深度体检项", .neutral)
                    )

                    // Timezone
                    let dev = controller.openReport?.deviceConsistency
                    MetricRow(
                        label: "本地时区一致性",
                        value: dev?.localTimezone ?? "",
                        badge: dev == nil
                            ? ("—", .neutral)
                            : (dev!.isChinaMainlandTimezone ? ("大陆时区", .warning) : (dev!.timezoneMatched == false ? ("略有偏差", .neutral) : ("一致", .safe)))
                    )

                    // Service Status
                    if let ind = controller.openReport?.claudeServiceIndicator {
                        MetricRow(
                            label: "Claude 官方状态",
                            value: "",
                            badge: ind == "none" ? ("全部正常", .safe) : (ind, .warning)
                        )
                    }
                }
            }
        }
    }

    private func securityBoolRow(_ label: String, flag: Bool?) -> some View {
        let badge: (String, SemanticBadgeTone) = {
            guard let flag else { return ("未知", .neutral) }
            return flag ? ("检测到", .warning) : ("未检测到", .safe)
        }()
        return MetricRow(label: label, value: "", badge: badge)
    }

    // MARK: - Section 4: Bottom Inspector Tabs

    private var bottomInspectorSection: some View {
        let currentTab = InspectorTab(rawValue: controller.selectedDashboardTab) ?? .evidence
        return LiquidGlassCard(cornerRadius: 18, padding: 18) {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Picker("诊断详情", selection: $controller.selectedDashboardTab) {
                        ForEach(InspectorTab.allCases) { tab in
                            Text(tab.title).tag(tab.rawValue)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 460)

                    Spacer()

                    if currentTab == .history && !controller.ipHistory.isEmpty {
                        Button("清除本地历史") {
                            controller.clearIPHistory()
                        }
                        .buttonStyle(.glass)
                        .controlSize(.small)
                    }
                }

                switch currentTab {
                case .evidence:
                    evidenceListView
                case .processes:
                    processesAndSocketsView
                case .history:
                    ipHistoryListView
                }
            }
        }
    }

    private var evidenceListView: some View {
        let openChecks = controller.openReport?.checks ?? []
        let closeChecks = controller.closeReport?.checks ?? []
        let allChecks = openChecks + closeChecks

        return VStack(alignment: .leading, spacing: 8) {
            if allChecks.isEmpty {
                Text("暂无检测记录，请点击右上角「快速检测」或「深度全量体检」。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 12)
            } else {
                ForEach(allChecks) { item in
                    HStack(alignment: .top, spacing: 10) {
                        Text(item.severity.icon)
                            .font(.callout)
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 8) {
                                Text("[\(item.category)] \(item.title)")
                                    .font(.callout.weight(.semibold))
                            }
                            Text(item.detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            if let rem = item.remediation {
                                Text("💡 修复建议：\(rem)")
                                    .font(.caption)
                                    .foregroundStyle(.orange)
                            }
                        }
                        Spacer()
                    }
                    .padding(.vertical, 5)
                    Divider().opacity(0.25)
                }
            }
        }
    }

    private var processesAndSocketsView: some View {
        let procs = controller.closeReport?.processes ?? []
        let sockets = controller.closeReport?.claudeSockets ?? []
        let browserSocks = controller.closeReport?.browserAnthropicSockets ?? []

        return VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("监控覆盖范围：Claude Desktop · Helper 全系 · Squirrel/ShipIt 更新器 · Chrome 扩展宿主 · Crashpad · Claude Code CLI (/opt/homebrew/bin/claude)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
            }

            if procs.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                    Text("当前没有任何运行中的 Claude 家族进程。")
                        .font(.callout.weight(.medium))
                }
                .padding(.vertical, 6)
            } else {
                ForEach(procs) { proc in
                    HStack(spacing: 12) {
                        StatusBadgePill(
                            text: proc.isStopped ? "已冻结 (SIGSTOP)" : "运行中",
                            tone: proc.isStopped ? .frozen : .warning
                        )
                        Text("PID \(proc.pid)")
                            .font(.callout.monospacedDigit().weight(.semibold))
                            .frame(width: 78, alignment: .leading)
                        Text(proc.kind.rawValue)
                            .font(.callout.weight(.medium))
                            .frame(width: 170, alignment: .leading)
                        Text(proc.commandLine)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                    }
                    .padding(.vertical, 3)
                }
            }

            if !sockets.isEmpty {
                Divider().opacity(0.3)
                Text("活跃 Claude 外部套接字 (\(sockets.count) 条)：")
                    .font(.caption.weight(.semibold))
                ForEach(sockets.prefix(8)) { s in
                    Text("• \(s.processName)[\(s.pid)] \(s.protocolName) \(s.localEndpoint) -> \(s.remoteEndpoint) (\(s.state))")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }

            if !browserSocks.isEmpty {
                Divider().opacity(0.3)
                Text("⚠️ 浏览器到 Anthropic 网段的活跃连接（关代理前建议关闭浏览器 claude.ai 标签页）：")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.orange)
                ForEach(browserSocks.prefix(5)) { s in
                    Text("• \(s.processName)[\(s.pid)] -> \(s.remoteEndpoint) (\(s.state))")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var ipHistoryListView: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("100% 本地隐私存储（保存在 ~/Library/Application Support/ClaudeGuard/ip_history.json，绝不向第三方上报会话关联）")
                .font(.caption)
                .foregroundStyle(.secondary)

            if controller.ipHistory.isEmpty {
                Text("暂无历史记录。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 8)
            } else {
                ForEach(controller.ipHistory) { entry in
                    HStack(spacing: 12) {
                        Text(RestrictedRegions.flagEmoji(for: entry.countryCode))
                        Text(RestrictedRegions.maskIPAddress(entry.ip, enabled: controller.maskIPInUI))
                            .font(.callout.monospaced().weight(.semibold))
                            .frame(width: 155, alignment: .leading)
                        if let score = entry.trustScore {
                            StatusBadgePill(
                                text: "评分 \(score)",
                                tone: score >= 50 ? .safe : (score >= 25 ? .warning : .danger)
                            )
                        }
                        Text(entry.location)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                        Spacer()
                        Text(entry.timestamp.formatted(date: .abbreviated, time: .shortened))
                            .font(.caption2.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 3)
                }
            }
        }
    }

    // MARK: - Tone Helpers

    private var openTone: SemanticBadgeTone {
        guard let v = controller.openReport?.verdict else { return .neutral }
        switch v {
        case .go: return .safe
        case .goWithWarnings: return .warning
        case .noGo: return .danger
        case .frozenEmergency: return .frozen
        }
    }

    private var closeTone: SemanticBadgeTone {
        guard let s = controller.closeReport?.status else { return .neutral }
        switch s {
        case .safeToCloseProxy: return .safe
        case .doNotCloseProxy: return .danger
        case .frozenNeedsAction: return .frozen
        }
    }

    private var closeStatusLabel: String {
        guard let s = controller.closeReport?.status else { return "扫描中..." }
        switch s {
        case .safeToCloseProxy: return "✅ 可安全关闭代理"
        case .doNotCloseProxy: return "⛔️ 严禁关闭代理"
        case .frozenNeedsAction: return "❄️ 冻结待处置"
        }
    }
}
