import SwiftUI
import AppKit
import ClaudeGuardCore

public struct MenuBarPopoverView: View {
    @Bindable var controller: ClaudeLifecycleController
    @Environment(\.openWindow) private var openWindow

    public init(controller: ClaudeLifecycleController) {
        self.controller = controller
    }

    public var body: some View {
        GlassEffectContainer {
            VStack(alignment: .leading, spacing: 14) {
                // Header
                HStack(spacing: 10) {
                    Image(systemName: headerSymbol)
                        .font(.title2.weight(.semibold))
                        .foregroundStyle(headerColor)

                    VStack(alignment: .leading, spacing: 2) {
                        Text("Claude Guard")
                            .font(.headline.weight(.bold))
                        Text(headerSubtitle)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }

                    Spacer()

                    Button {
                        controller.maskIPInUI.toggle()
                    } label: {
                        Image(systemName: controller.maskIPInUI ? "eye.slash.fill" : "eye")
                            .help("隐藏 / 显示出口 IP 后段")
                    }
                    .buttonStyle(.glass)
                    .controlSize(.small)

                    Button {
                        Task { await controller.runOpenCheck(deep: false) }
                    } label: {
                        Image(systemName: "arrow.clockwise")
                            .help("立即重新检测")
                    }
                    .buttonStyle(.glass)
                    .controlSize(.small)
                    .disabled(controller.isBusy)
                }

                // Prominent Closed-Loop Stage Banner
                stageHighlightBanner

                // Two-Gate Cards
                HStack(spacing: 10) {
                    LiquidGlassCard(tint: openGateTone.color, cornerRadius: 14, padding: 11) {
                        VStack(alignment: .leading, spacing: 5) {
                            HStack {
                                Text("打开 Claude")
                                    .font(.caption.weight(.medium))
                                    .foregroundStyle(.secondary)
                                Spacer()
                                StatusBadgePill(text: openGateBadgeText, tone: openGateTone)
                            }
                            if let trace = controller.openReport?.claudeTrace, let ip = trace.ip {
                                Text("\(RestrictedRegions.flagEmoji(for: trace.loc)) \(RestrictedRegions.maskIPAddress(ip, enabled: controller.maskIPInUI))")
                                    .font(.callout.weight(.semibold).monospacedDigit())
                                    .lineLimit(1)
                            } else {
                                Text(controller.openReport?.transportMode.rawValue ?? "等待检测...")
                                    .font(.caption)
                                    .lineLimit(1)
                            }
                            Text(trustScoreSubtext)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                    }

                    LiquidGlassCard(tint: closeGateTone.color, cornerRadius: 14, padding: 11) {
                        VStack(alignment: .leading, spacing: 5) {
                            HStack {
                                Text("关闭代理")
                                    .font(.caption.weight(.medium))
                                    .foregroundStyle(.secondary)
                                Spacer()
                                StatusBadgePill(text: closeGateBadgeText, tone: closeGateTone)
                            }
                            let procCount = controller.closeReport?.processes.count ?? 0
                            let sockCount = controller.closeReport?.claudeSockets.count ?? 0
                            Text(procCount == 0 && sockCount == 0 ? "0 进程 · 0 活跃连接" : "\(procCount) 进程 · \(sockCount) 连接")
                                .font(.callout.weight(.semibold).monospacedDigit())
                                .lineLimit(1)
                            Text(procCount == 0 ? "现在关代理完全安全" : "运行中严禁关闭代理")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                    }
                }

                // Primary Closed-Loop Action Button
                primaryActionSection

                Divider().opacity(0.4)

                // Footer Controls
                HStack(spacing: 8) {
                    Toggle("断路器守护", isOn: $controller.activeProtectionEnabled)
                        .toggleStyle(.switch)
                        .controlSize(.mini)
                        .font(.caption)

                    Spacer()

                    Button("打开诊断中心") {
                        openWindow(id: "dashboard")
                        NSApp.activate(ignoringOtherApps: true)
                    }
                    .buttonStyle(.glass)
                    .controlSize(.small)

                    Button("退出") {
                        NSApplication.shared.terminate(nil)
                    }
                    .buttonStyle(.plain)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
            .padding(16)
            .frame(width: 396)
        }
        .onAppear {
            controller.refreshFastLocalState()
        }
    }

    // MARK: - Subviews & Computed Helpers

    @ViewBuilder
    private var stageHighlightBanner: some View {
        switch controller.stage {
        case .safeToTurnOffProxy:
            LiquidGlassCard(tint: .green, cornerRadius: 14, padding: 12) {
                HStack(spacing: 10) {
                    Image(systemName: "checkmark.seal.fill")
                        .font(.title2)
                        .foregroundStyle(.green)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("✅ Claude 已彻底关闭，现在可以安全关闭代理！")
                            .font(.subheadline.weight(.bold))
                            .foregroundStyle(.green)
                        Text("全部主进程、Helper、更新器及外部网络连接已排空并完成静默核验。")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        case let .quittingDraining(step, _, elapsed):
            LiquidGlassCard(tint: .blue, cornerRadius: 14, padding: 12) {
                HStack(spacing: 10) {
                    ProgressView()
                        .controlSize(.small)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("正在安全退出并验证网络排空 (\(elapsed)s)...")
                            .font(.subheadline.weight(.semibold))
                        Text(step)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        case let .checkingOpenGate(step):
            LiquidGlassCard(tint: .blue, cornerRadius: 14, padding: 12) {
                HStack(spacing: 10) {
                    ProgressView()
                        .controlSize(.small)
                    Text(step)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        case let .emergencyFrozen(reason, count):
            LiquidGlassCard(tint: .cyan, cornerRadius: 14, padding: 12) {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Image(systemName: "snowflake")
                            .foregroundStyle(.cyan)
                        Text("已紧急冻结 \(count) 个 Claude 进程")
                            .font(.subheadline.weight(.bold))
                            .foregroundStyle(.cyan)
                    }
                    Text(reason)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        case let .blockedCannotOpen(reason):
            LiquidGlassCard(tint: .red, cornerRadius: 14, padding: 12) {
                HStack(spacing: 8) {
                    Image(systemName: "hand.raised.fill")
                        .foregroundStyle(.red)
                    Text(reason)
                        .font(.caption.weight(.medium))
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        case .guardingActiveClaude:
            LiquidGlassCard(tint: .mint, cornerRadius: 14, padding: 10) {
                HStack(spacing: 8) {
                    Image(systemName: "bolt.shield.fill")
                        .foregroundStyle(.green)
                    Text("Claude 正在运行 · 实时守护中（使用完请点下方安全退出，切勿先关代理）")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        case .idle, .launchingClaude:
            EmptyView()
        }
    }

    @ViewBuilder
    private var primaryActionSection: some View {
        let hasRunningClaude = !(controller.closeReport?.processes.filter { !$0.isStopped }.isEmpty ?? true)
        let hasFrozenClaude = !(controller.closeReport?.processes.filter(\.isStopped).isEmpty ?? true)

        if hasFrozenClaude {
            HStack(spacing: 8) {
                Button {
                    Task { await controller.emergencyForceCloseFrozenClaude() }
                } label: {
                    Label("零发包强退", systemImage: "bolt.slash.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glass)
                .controlSize(.large)

                Button {
                    Task { _ = await controller.verifyProxyAndResumeFrozenClaude() }
                } label: {
                    Label("恢复代理后解冻", systemImage: "play.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .tint(.cyan)
                .controlSize(.large)
            }
        } else if hasRunningClaude {
            Button {
                Task { _ = await controller.safeQuitClaudeAndVerifyDrain() }
            } label: {
                Label("安全关闭 Claude（排空后提示可关代理）", systemImage: "power.circle.fill")
                    .font(.callout.weight(.semibold))
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .tint(.orange)
            .controlSize(.large)
            .disabled(controller.isBusy)
        } else {
            VStack(spacing: 8) {
                Button {
                    Task { _ = await controller.checkAndOpenClaude() }
                } label: {
                    Label("安全检测并打开 Claude Desktop", systemImage: "paperplane.fill")
                        .font(.callout.weight(.semibold))
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .tint(openGateTone == .danger ? .blue : .green)
                .controlSize(.large)
                .disabled(controller.isBusy)

                if controller.openReport?.verdict == .noGo,
                   let clients = controller.openReport?.proxyClients, !clients.isEmpty {
                    HStack(spacing: 6) {
                        Text("先开代理：")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                        ForEach(clients.prefix(2)) { app in
                            Button("启动 \(app.name)") {
                                controller.openProxyClient(app)
                            }
                            .buttonStyle(.glass)
                            .controlSize(.small)
                        }
                        Spacer()
                    }
                }
            }
        }
    }

    private var openGateTone: SemanticBadgeTone {
        guard let v = controller.openReport?.verdict else { return .neutral }
        switch v {
        case .go: return .safe
        case .goWithWarnings: return .warning
        case .noGo: return .danger
        case .frozenEmergency: return .frozen
        }
    }

    private var openGateBadgeText: String {
        guard let v = controller.openReport?.verdict else { return "待检" }
        switch v {
        case .go: return "安全"
        case .goWithWarnings: return "有提醒"
        case .noGo: return "禁开"
        case .frozenEmergency: return "已冻结"
        }
    }

    private var closeGateTone: SemanticBadgeTone {
        guard let s = controller.closeReport?.status else { return .neutral }
        switch s {
        case .safeToCloseProxy: return .safe
        case .doNotCloseProxy: return .danger
        case .frozenNeedsAction: return .frozen
        }
    }

    private var closeGateBadgeText: String {
        guard let s = controller.closeReport?.status else { return "待检" }
        switch s {
        case .safeToCloseProxy: return "可关代理"
        case .doNotCloseProxy: return "严禁关"
        case .frozenNeedsAction: return "待处置"
        }
    }

    private var trustScoreSubtext: String {
        if let risk = controller.openReport?.ipRisk, let s = risk.trustScore {
            return "评分 \(s)/100 · \(risk.ipTypeLabel)"
        }
        return controller.openReport?.transportMode.rawValue ?? "点击按钮执行实时双栈验证"
    }

    private var headerSymbol: String {
        if case .emergencyFrozen = controller.stage { return "snowflake.circle.fill" }
        if controller.openReport?.verdict == .noGo { return "xmark.shield.fill" }
        if controller.openReport?.verdict == .goWithWarnings { return "exclamationmark.shield.fill" }
        return "checkmark.shield.fill"
    }

    private var headerColor: Color {
        if case .emergencyFrozen = controller.stage { return .cyan }
        if controller.openReport?.verdict == .noGo { return .red }
        if controller.openReport?.verdict == .goWithWarnings { return .orange }
        return .green
    }

    private var headerSubtitle: String {
        if let r = controller.openReport {
            return r.summaryHeadline
        }
        return "正在初始化本地路由与门禁状态..."
    }
}
