import Foundation
import AppKit
import ClaudeGuardCore

@main
struct ClaudeGuardCLI {
    static func main() async {
        let args = Array(CommandLine.arguments.dropFirst())
        let command = args.first(where: { !$0.hasPrefix("-") }) ?? "status"
        let jsonMode = args.contains("--json")
        let withNet = args.contains("--net")
        let deepFlag = args.contains("--deep")
        let maskIP = args.contains("--mask-ip")
        let samples = parseIntOption(args: args, name: "--samples") ?? (command == "deep" || deepFlag ? 10 : 6)
        let timeout = Double(parseIntOption(args: args, name: "--timeout") ?? 5)

        if args.contains("-h") || args.contains("--help") || command == "help" {
            printUsage()
            Foundation.exit(0)
        }

        let evaluator = GateEvaluator()

        switch command {
        case "status":
            let openRep = await evaluator.evaluateOpenGate(includeNetwork: withNet, deep: false, sampleCount: withNet ? 3 : 1, timeout: timeout)
            let closeRep = evaluator.evaluateCloseGate()
            if jsonMode {
                struct CombinedStatus: Encodable {
                    let openGate: OpenGateReport
                    let closeGate: CloseGateReport
                }
                print(ReportFormatter.encodeJSON(CombinedStatus(openGate: openRep, closeGate: closeRep)))
            } else {
                print(ReportFormatter.renderCloseReport(closeRep))
                print("")
                print(ReportFormatter.renderOpenReport(openRep, maskIP: maskIP))
            }
            let code = max(openRep.verdict.exitCode, closeRep.status.exitCode)
            Foundation.exit(code)

        case "open-check":
            let rep = await evaluator.evaluateOpenGate(includeNetwork: true, deep: deepFlag, sampleCount: samples, timeout: timeout)
            if jsonMode {
                print(ReportFormatter.encodeJSON(rep))
            } else {
                print(ReportFormatter.renderOpenReport(rep, maskIP: maskIP))
            }
            Foundation.exit(rep.verdict.exitCode)

        case "close-check":
            let rep = evaluator.evaluateCloseGate()
            if jsonMode {
                print(ReportFormatter.encodeJSON(rep))
            } else {
                print(ReportFormatter.renderCloseReport(rep))
            }
            Foundation.exit(rep.status.exitCode)

        case "open":
            let rep = await evaluator.evaluateOpenGate(includeNetwork: true, deep: deepFlag, sampleCount: samples, timeout: timeout)
            if !jsonMode {
                print(ReportFormatter.renderOpenReport(rep, maskIP: maskIP))
            }
            guard rep.claudeInstalled && (rep.verdict == .go || rep.verdict == .goWithWarnings) else {
                if jsonMode { print(ReportFormatter.encodeJSON(rep)) }
                Foundation.exit(rep.verdict.exitCode == 0 ? 2 : rep.verdict.exitCode)
            }
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/open")
            proc.arguments = ["-a", "/Applications/Claude.app"]
            try? proc.run()
            proc.waitUntilExit()
            if jsonMode {
                print(ReportFormatter.encodeJSON(rep))
            } else {
                print("\n🚀 已验证安全并启动 /Applications/Claude.app（使用期间切勿直接关闭代理）")
            }
            Foundation.exit(rep.verdict.exitCode)

        case "quit":
            let controller = await MainActor.run { ClaudeLifecycleController(evaluator: evaluator) }
            if !jsonMode {
                print("🛑 正在请求安全退出 Claude Desktop 并核验全进程/Socket 排空...")
            }
            let finalClose = await controller.safeQuitClaudeAndVerifyDrain(maxWaitSeconds: 30)
            if jsonMode {
                print(ReportFormatter.encodeJSON(finalClose))
            } else {
                print(ReportFormatter.renderCloseReport(finalClose))
            }
            Foundation.exit(finalClose.status.exitCode)

        case "deep":
            let rep = await evaluator.evaluateOpenGate(includeNetwork: true, deep: true, sampleCount: samples, timeout: max(timeout, 6.0))
            if jsonMode {
                print(ReportFormatter.encodeJSON(rep))
            } else {
                print(ReportFormatter.renderOpenReport(rep, maskIP: maskIP))
            }
            Foundation.exit(rep.verdict.exitCode)

        case "watch":
            print("👁️  正在持续监控 Claude 与代理状态（按 Ctrl+C 停止）...")
            var lastSignature = ""
            while true {
                let openRep = await evaluator.evaluateOpenGate(includeNetwork: withNet, deep: false, sampleCount: 1, timeout: timeout)
                let closeRep = evaluator.evaluateCloseGate()
                let sig = "\(openRep.verdict.rawValue)|\(closeRep.status.rawValue)|\(closeRep.processes.count)"
                if sig != lastSignature {
                    lastSignature = sig
                    let ts = ISO8601DateFormatter().string(from: Date())
                    print("[\(ts)] 开Claude: \(openRep.verdict.badgeSymbol) \(openRep.verdict.rawValue) | 关代理: \(closeRep.status.badgeSymbol) \(closeRep.summaryHeadline)")
                }
                try? await Task.sleep(for: .seconds(3))
            }

        case "selftest":
            let (allPass, outcomes) = await BuiltinSelfTest.runAll()
            for item in outcomes {
                print("\(item.passed ? "✅ PASS" : "❌ FAIL") · \(item.name) — \(item.detail)")
            }
            print("\n总结: \(outcomes.filter(\.passed).count)/\(outcomes.count) 通过")
            Foundation.exit(allPass ? 0 : 2)

        default:
            fputs("未知子命令: \(command)\n\n", stderr)
            printUsage()
            Foundation.exit(2)
        }
    }

    private static func parseIntOption(args: [String], name: String) -> Int? {
        guard let idx = args.firstIndex(of: name), idx + 1 < args.count else { return nil }
        return Int(args[idx + 1])
    }

    private static func printUsage() {
        print("""
        Claude Guard (macOS 26+ Native CLI) — Claude / 代理安全开关门禁工具

        用法:
          claude-guard <command> [options]

        命令:
          status        查看能否安全关代理 & 能否安全开 Claude（默认仅本地，加 --net 含联网探测）
          open-check    打开前安全检测（含双栈出口、分流一致性、IP 纯净度、轮换采样）
          close-check   关闭代理前安全检查（Claude 全家桶进程、Socket 排空、日志静默）
          open          执行 open-check，通过后自动启动 Claude Desktop
          quit          优雅退出 Claude -> 等待全进程/Socket 排空 -> 报告“现在可以关闭代理”
          deep          全量深度检测（含中国出口对比、DNS 泄露、STUN UDP、服务状态）
          watch         持续监控状态变化（加 --net 开启周期出口核验）
          selftest      运行离线单元测试套件（不联网）

        参数:
          --json        输出结构化 JSON（便于快捷指令与脚本集成）
          --net         在 status / watch 中启用实时网络出口探测
          --deep        在 open-check / open 中附加全量深度检测
          --samples N   出口轮换采样连接数（默认 6，deep 默认 10）
          --timeout N   单次网络探测超时秒数（默认 5）
          --mask-ip     打码隐藏 IP 后两段
        """)
    }
}
