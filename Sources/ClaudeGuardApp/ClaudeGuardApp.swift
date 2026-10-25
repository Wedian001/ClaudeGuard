import SwiftUI
import AppKit
import ClaudeGuardCore

@MainActor
final class ClaudeGuardAppDelegate: NSObject, NSApplicationDelegate {
    let controller = ClaudeLifecycleController()
    let emergencyWindow = EmergencyFreezeWindowController()

    func applicationDidFinishLaunching(_ notification: Notification) {
        controller.onEmergencyFreezeAlert = { [weak self] _ in
            guard let self else { return }
            self.emergencyWindow.present(controller: self.controller)
        }
        controller.startServices()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // Keep MenuBarExtra capsule running even when dashboard window is closed
        false
    }
}

@main
struct ClaudeGuardApp: App {
    @NSApplicationDelegateAdaptor(ClaudeGuardAppDelegate.self) private var appDelegate

    var body: some Scene {
        Window("Claude Guard · 安全门禁与主动守护中心", id: "dashboard") {
            MainDashboardView(controller: appDelegate.controller)
        }
        .defaultSize(width: 980, height: 760)
        .windowToolbarStyle(.unified)

        MenuBarExtra {
            MenuBarPopoverView(controller: appDelegate.controller)
        } label: {
            MenuBarStatusLabel(controller: appDelegate.controller)
        }
        .menuBarExtraStyle(.window)
    }
}

struct MenuBarStatusLabel: View {
    @Bindable var controller: ClaudeLifecycleController

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: iconName)
            Text(shortStatusTag)
                .font(.caption2.monospacedDigit())
        }
    }

    private var iconName: String {
        if case .emergencyFrozen = controller.stage {
            return "snowflake"
        }
        if case .safeToTurnOffProxy = controller.stage {
            return "checkmark.shield.fill"
        }
        if let v = controller.openReport?.verdict {
            switch v {
            case .go: return "checkmark.shield.fill"
            case .goWithWarnings: return "exclamationmark.shield.fill"
            case .noGo: return "xmark.shield.fill"
            case .frozenEmergency: return "snowflake"
            }
        }
        return "shield.lefthalf.filled"
    }

    private var shortStatusTag: String {
        if case .emergencyFrozen = controller.stage { return "已冻结" }
        if case .safeToTurnOffProxy = controller.stage { return "可关代理" }
        let running = !(controller.closeReport?.processes.isEmpty ?? true)
        if running { return "守护中" }
        guard let v = controller.openReport?.verdict else { return "Guard" }
        switch v {
        case .go: return "安全"
        case .goWithWarnings: return "可开"
        case .noGo: return "禁开"
        case .frozenEmergency: return "冻结"
        }
    }
}
