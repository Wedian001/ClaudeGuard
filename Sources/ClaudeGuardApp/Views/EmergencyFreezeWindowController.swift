import SwiftUI
import AppKit
import ClaudeGuardCore

@MainActor
public final class EmergencyFreezeWindowController {
    private var panel: NSPanel?

    public init() {}

    public func present(controller: ClaudeLifecycleController) {
        if let existing = panel {
            existing.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let contentView = EmergencyFreezeAlertView(
            controller: controller,
            onDismissWindow: { [weak self] in
                self?.close()
            }
        )
        let hosting = NSHostingController(rootView: contentView)

        let newPanel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 500, height: 340),
            styleMask: [.titled, .closable, .fullSizeContentView, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        newPanel.title = "ClaudeGuard 紧急断路器保护"
        newPanel.titlebarAppearsTransparent = true
        newPanel.isMovableByWindowBackground = true
        newPanel.level = .floating
        newPanel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        newPanel.backgroundColor = .clear
        newPanel.isOpaque = false
        newPanel.contentViewController = hosting
        newPanel.center()
        newPanel.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        self.panel = newPanel
    }

    public func close() {
        panel?.close()
        panel = nil
    }
}

struct EmergencyFreezeAlertView: View {
    @Bindable var controller: ClaudeLifecycleController
    let onDismissWindow: () -> Void

    var body: some View {
        GlassEffectContainer {
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 14) {
                    Image(systemName: "snowflake.circle.fill")
                        .font(.system(size: 42))
                        .foregroundStyle(.cyan)
                        .symbolEffect(.pulse)

                    VStack(alignment: .leading, spacing: 4) {
                        Text("⚡️ 主动断路器已紧急冻结 Claude")
                            .font(.title3.weight(.bold))
                        Text("所有 Claude 进程线程已在内核态挂起 (SIGSTOP)，已阻止直连遥测发包")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }

                LiquidGlassCard(tint: .cyan, cornerRadius: 14, padding: 14) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(freezeReasonText)
                            .font(.callout.weight(.medium))
                            .fixedSize(horizontal: false, vertical: true)

                        if let procs = controller.closeReport?.processes, !procs.isEmpty {
                            Text("受保护挂起进程：\(procs.map { "\($0.executableName) (PID \($0.pid))" }.prefix(4).joined(separator: " · "))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                if let clients = controller.openReport?.proxyClients, !clients.isEmpty {
                    HStack(spacing: 8) {
                        Text("快捷恢复代理：")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        ForEach(clients.prefix(3)) { client in
                            Button("打开 \(client.name)") {
                                controller.openProxyClient(client)
                            }
                            .buttonStyle(.glass)
                            .controlSize(.small)
                        }
                    }
                }

                Spacer(minLength: 4)

                HStack(spacing: 12) {
                    Button {
                        Task {
                            await controller.emergencyForceCloseFrozenClaude()
                            onDismissWindow()
                        }
                    } label: {
                        Label("不恢复代理 · 零发包强制关闭", systemImage: "bolt.slash.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.glass)
                    .controlSize(.large)
                    .disabled(controller.isBusy)

                    Button {
                        Task {
                            let ok = await controller.verifyProxyAndResumeFrozenClaude()
                            if ok {
                                onDismissWindow()
                            }
                        }
                    } label: {
                        Label("已恢复代理 · 验证并解冻继续", systemImage: "play.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.glassProminent)
                    .tint(.cyan)
                    .controlSize(.large)
                    .disabled(controller.isBusy)
                }
            }
            .padding(24)
            .frame(width: 500)
            .frame(minHeight: 330)
            .background(.ultraThinMaterial)
        }
    }

    private var freezeReasonText: String {
        if case let .emergencyFrozen(reason, _) = controller.stage {
            return reason
        }
        return controller.lastFreezeEvent?.reason ?? "检测到代理中断或直连风险，进程已被安全冻结。"
    }
}
