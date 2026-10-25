import Foundation
import AppKit

public protocol ProcessAndEnvironmentInspecting: Sendable {
    func isClaudeDesktopInstalled() -> (installed: Bool, version: String?)
    func scanClaudeProcesses() -> [ClaudeProcessInfo]
    /// False when the process table could not be read; callers must fail closed.
    func isProcessScanAvailable() -> Bool
    func scanActiveSockets(claudePIDs: Set<Int32>) -> (claudeSockets: [ActiveSocketInfo], browserAnthropicSockets: [ActiveSocketInfo])
    func inspectClaudeLogs() -> LogScanResult
    func inspectDeviceConsistency(exitCountryCode: String?, exitExactTimezone: String?) -> DeviceConsistencyResult
}

public extension ProcessAndEnvironmentInspecting {
    /// Test doubles and offline environments are healthy by default.
    func isProcessScanAvailable() -> Bool { true }
}

public struct ProcessAndSocketScanner: ProcessAndEnvironmentInspecting {
    private let shell: any ShellCommandRunning
    private let claudeAppPath: String
    private let claudeLogsDir: String

    public init(
        shell: any ShellCommandRunning = LiveShellRunner(),
        claudeAppPath: String = "/Applications/Claude.app",
        claudeLogsDir: String = (NSHomeDirectory() as NSString).appendingPathComponent("Library/Logs/Claude")
    ) {
        self.shell = shell
        self.claudeAppPath = claudeAppPath
        self.claudeLogsDir = claudeLogsDir
    }

    public func isClaudeDesktopInstalled() -> (installed: Bool, version: String?) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: claudeAppPath) else {
            return (false, nil)
        }
        let plistPath = (claudeAppPath as NSString).appendingPathComponent("Contents/Info.plist")
        if let dict = NSDictionary(contentsOfFile: plistPath) {
            let shortVer = dict["CFBundleShortVersionString"] as? String
            let buildVer = dict["CFBundleVersion"] as? String
            if let s = shortVer, let b = buildVer, s != b {
                return (true, "\(s) (\(b))")
            }
            return (true, shortVer ?? buildVer)
        }
        return (true, nil)
    }

    public func isProcessScanAvailable() -> Bool {
        let probe = shell.run(executable: "/bin/ps", arguments: ["-axo", "pid="], timeoutSeconds: 2.0)
        return probe.exitCode == 0
    }

    public func scanClaudeProcesses() -> [ClaudeProcessInfo] {
        let currentPID = ProcessInfo.processInfo.processIdentifier
        let psResult = shell.run(
            executable: "/bin/ps",
            arguments: ["-axo", "pid=,ppid=,stat=,comm=,args="],
            timeoutSeconds: 2.5
        )
        return Self.parsePSOutput(psResult.stdout, excludingPID: currentPID)
    }

    public static func parsePSOutput(_ output: String, excludingPID: Int32 = -1) -> [ClaudeProcessInfo] {
        var found: [ClaudeProcessInfo] = []

        for rawLine in output.split(whereSeparator: \.isNewline) {
            let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }

            // Parse first 3 whitespace-separated tokens: pid, ppid, stat
            let parts = trimmed.split(maxSplits: 3, omittingEmptySubsequences: true, whereSeparator: \.isWhitespace)
            guard parts.count >= 4,
                  let pid = Int32(parts[0]),
                  let ppid = Int32(parts[1]) else {
                continue
            }
            if pid == excludingPID { continue }

            let stat = String(parts[2])
            let remainder = String(parts[3])

            // Never match our own guard process family or unrelated tools
            if remainder.contains("ClaudeGuard") || remainder.contains("claude-guard") {
                continue
            }

            if let kind = classifyCommandLine(remainder) {
                let execName = extractExecutableName(from: remainder)
                found.append(
                    ClaudeProcessInfo(
                        pid: pid,
                        ppid: ppid,
                        kind: kind,
                        executableName: execName,
                        commandLine: remainder,
                        stateCode: stat
                    )
                )
            }
        }
        return found
    }

    public static func classifyCommandLine(_ cmd: String) -> ClaudeProcessKind? {
        if cmd.contains("/Claude.app/Contents/Frameworks/Claude Helper") {
            return .desktopHelper
        }
        if cmd.contains("/Claude.app/Contents/Helpers/chrome-native-host") {
            return .chromeNativeHost
        }
        if cmd.contains("/Claude.app/Contents/Helpers/app-cu-helper") {
            return .computerUseHelper
        }
        if cmd.contains("/Claude.app/Contents/Helpers/claude-ssh-askpass") {
            return .sshAskPass
        }
        if cmd.contains("chrome_crashpad_handler") &&
            (cmd.contains("/Claude.app/") || cmd.contains("Application Support/Claude")) {
            return .crashpadHandler
        }
        if cmd.contains("ShipIt") &&
            (cmd.contains("com.anthropic.claudefordesktop") || cmd.contains("/Claude.app/")) {
            return .shipItUpdater
        }
        if cmd.contains("/Claude.app/Contents/MacOS/Claude") {
            return .desktopMain
        }
        // Claude Code CLI detection (Homebrew Cask, npm global, ~/.local/bin/claude, or direct `claude` invocation)
        if isClaudeCodeCLICommand(cmd) {
            return .claudeCodeCLI
        }
        return nil
    }

    private static func isClaudeCodeCLICommand(_ cmd: String) -> Bool {
        if cmd.contains("/Caskroom/claude-code/") ||
            cmd.contains("@anthropic-ai/claude-code") ||
            cmd.contains("/opt/homebrew/bin/claude") ||
            cmd.contains("/usr/local/bin/claude") ||
            cmd.contains("/.local/bin/claude") ||
            cmd.contains("/.claude/local/claude") {
            return true
        }
        // Check if binary token itself ends with `/claude` or equals `claude`
        let tokens = cmd.split(whereSeparator: \.isWhitespace)
        for token in tokens.prefix(3) {
            let t = String(token)
            if t == "claude" || t.hasSuffix("/bin/claude") {
                return true
            }
        }
        return false
    }

    private static func extractExecutableName(from remainder: String) -> String {
        if remainder.contains("Claude Helper (Renderer)") { return "Claude Helper (Renderer)" }
        if remainder.contains("Claude Helper (GPU)") { return "Claude Helper (GPU)" }
        if remainder.contains("Claude Helper (Plugin)") { return "Claude Helper (Plugin)" }
        if remainder.contains("Claude Helper") { return "Claude Helper" }
        let firstToken = remainder.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? remainder
        return (firstToken as NSString).lastPathComponent
    }

    public func scanActiveSockets(claudePIDs: Set<Int32>) -> (claudeSockets: [ActiveSocketInfo], browserAnthropicSockets: [ActiveSocketInfo]) {
        let lsofRes = shell.run(
            executable: "/usr/sbin/lsof",
            arguments: ["-nP", "-iTCP", "-iUDP"],
            timeoutSeconds: 3.0
        )
        return Self.parseLsofSockets(lsofRes.stdout, claudePIDs: claudePIDs)
    }

    public static func parseLsofSockets(
        _ output: String,
        claudePIDs: Set<Int32>
    ) -> (claudeSockets: [ActiveSocketInfo], browserAnthropicSockets: [ActiveSocketInfo]) {
        var claudeSockets: [ActiveSocketInfo] = []
        var browserSockets: [ActiveSocketInfo] = []

        for (index, rawLine) in output.split(whereSeparator: \.isNewline).enumerated() {
            if index == 0 && rawLine.hasPrefix("COMMAND") { continue }
            let cols = rawLine.split(omittingEmptySubsequences: true, whereSeparator: \.isWhitespace)
            guard cols.count >= 9, let pid = Int32(cols[1]) else { continue }

            let procName = String(cols[0])
            let proto = cols.first(where: { $0 == "TCP" || $0 == "UDP" }).map(String.init) ?? "TCP"

            // Name column is usually second to last (with `(ESTABLISHED)` last) or last
            var endpointPart = ""
            var statePart = ""
            if let last = cols.last, last.hasPrefix("(") && last.hasSuffix(")") {
                statePart = String(last.dropFirst().dropLast())
                endpointPart = String(cols[cols.count - 2])
            } else if let last = cols.last {
                endpointPart = String(last)
                statePart = proto == "UDP" ? "UDP" : "OPEN"
            }

            // Only care about outbound connections (`local->remote`)
            guard let arrowRange = endpointPart.range(of: "->") else { continue }
            let localEP = String(endpointPart[..<arrowRange.lowerBound])
            let remoteEP = String(endpointPart[arrowRange.upperBound...])

            // Ignore purely loopback local IPC sockets (127.0.0.1 -> 127.0.0.1) UNLESS owned by Claude talking to local proxy port!
            //Wait: if Claude is still talking to 127.0.0.1:7890 (system proxy), closing the proxy WILL break/leak! So ANY active connection owned by Claude PIDs (except closed/listen) matters!
            if statePart == "LISTEN" || statePart == "CLOSED" { continue }

            let isClaudePID = claudePIDs.contains(pid) || procName.lowercased().hasPrefix("claude")
            let remoteIP = extractIPFromEndpoint(remoteEP)
            let isAnthropicIP = isAnthropicOwnedIP(remoteIP)
            let lowerProc = procName.lowercased()
            let isBrowser = lowerProc.contains("chrome") || lowerProc.contains("google") ||
                lowerProc.contains("safari") || lowerProc.contains("webkit") ||
                lowerProc.contains("arc") || lowerProc.contains("firefox") ||
                lowerProc.contains("edge") || lowerProc.contains("microsoft") ||
                lowerProc.contains("brave") || lowerProc.contains("opera") || lowerProc.contains("vivaldi")

            let info = ActiveSocketInfo(
                pid: pid,
                processName: procName,
                protocolName: proto,
                localEndpoint: localEP,
                remoteEndpoint: remoteEP,
                state: statePart,
                isClaudeFamilyProcess: isClaudePID,
                isAnthropicIPRange: isAnthropicIP,
                isBrowserProcess: isBrowser
            )

            if isClaudePID {
                // Exclude localhost-to-localhost internal Electron IPC unless remote port looks like an external/proxy connection
                if !(localEP.hasPrefix("127.0.0.1:") && remoteEP.hasPrefix("127.0.0.1:") && statePart == "TIME_WAIT") {
                    claudeSockets.append(info)
                }
            } else if isAnthropicIP && isBrowser {
                browserSockets.append(info)
            }
        }

        return (claudeSockets, browserSockets)
    }

    private static func extractIPFromEndpoint(_ ep: String) -> String {
        if ep.hasPrefix("["), let closeIdx = ep.firstIndex(of: "]") {
            return String(ep[ep.index(after: ep.startIndex)..<closeIdx])
        }
        if let lastColon = ep.lastIndex(of: ":") {
            return String(ep[..<lastColon])
        }
        return ep
    }

    /// Checks Anthropic AS399358 blocks: 160.79.104.0/21 (160.79.104.0 - 160.79.111.255) and 2607:6bc0::/32
    public static func isAnthropicOwnedIP(_ ip: String) -> Bool {
        let lower = ip.lowercased()
        if lower.hasPrefix("2607:6bc0:") {
            return true
        }
        let octets = ip.split(separator: ".").compactMap { Int($0) }
        guard octets.count == 4 else { return false }
        return octets[0] == 160 && octets[1] == 79 && (104...111).contains(octets[2])
    }

    public func inspectClaudeLogs() -> LogScanResult {
        let mainLogPath = (claudeLogsDir as NSString).appendingPathComponent("main.log")
        let webLogPath = (claudeLogsDir as NSString).appendingPathComponent("claude.ai-web.log")
        let fm = FileManager.default

        guard fm.fileExists(atPath: mainLogPath) else {
            return LogScanResult(mainLogExists: false, secondsSinceLastWrite: nil, isQuietFor2Seconds: true)
        }

        var secondsAgo: Double?
        if let attrs = try? fm.attributesOfItem(atPath: mainLogPath),
           let modDate = attrs[.modificationDate] as? Date {
            secondsAgo = max(0, Date().timeIntervalSince(modDate))
        }

        let mainTail = Self.readLastBytes(path: mainLogPath, maxBytes: 65_536)
        let webTail = Self.readLastBytes(path: webLogPath, maxBytes: 65_536)
        return Self.analyzeLogContent(
            mainLogTail: mainTail,
            webLogTail: webTail,
            secondsSinceLastWrite: secondsAgo
        )
    }

    public static func analyzeLogContent(
        mainLogTail: String,
        webLogTail: String,
        secondsSinceLastWrite: Double?
    ) -> LogScanResult {
        let quiet = (secondsSinceLastWrite ?? 999.0) >= 2.0
        var lastMarker: String?
        var regionUnavailableCount = 0
        var auth403Count = 0
        var latestError: String?

        let combinedLines = (mainLogTail + "\n" + webLogTail).split(whereSeparator: \.isNewline)
        for rawLine in combinedLines {
            let line = String(rawLine)
            if line.contains("onQuitCleanup handlers done") {
                lastMarker = "onQuitCleanup handlers done"
            } else if line.contains("willQuit") {
                lastMarker = "willQuit"
            } else if line.contains("beforeQuit") {
                lastMarker = "beforeQuit"
            }

            if line.localizedCaseInsensitiveContains("region_unavailable") {
                regionUnavailableCount += 1
                latestError = String(line.prefix(160))
            }
            if line.contains("403") && (line.localizedCaseInsensitiveContains("telemetry") || line.localizedCaseInsensitiveContains("anthropic") || line.localizedCaseInsensitiveContains("claude")) {
                auth403Count += 1
                if latestError == nil {
                    latestError = String(line.prefix(160))
                }
            }
        }

        return LogScanResult(
            mainLogExists: true,
            secondsSinceLastWrite: secondsSinceLastWrite,
            isQuietFor2Seconds: quiet,
            lastQuitMarker: lastMarker,
            recentRegionUnavailableCount: regionUnavailableCount,
            recentAuth403Count: auth403Count,
            latestErrorLine: latestError
        )
    }

    private static func readLastBytes(path: String, maxBytes: Int) -> String {
        guard let handle = FileHandle(forReadingAtPath: path) else { return "" }
        defer { try? handle.close() }
        let endOffset = (try? handle.seekToEnd()) ?? 0
        let startOffset = endOffset > UInt64(maxBytes) ? endOffset - UInt64(maxBytes) : 0
        try? handle.seek(toOffset: startOffset)
        let data = (try? handle.readToEnd()) ?? Data()
        return String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
    }

    public func inspectDeviceConsistency(exitCountryCode: String?, exitExactTimezone: String?) -> DeviceConsistencyResult {
        let now = Date()
        let localTZ = TimeZone.current
        let localTzID = localTZ.identifier
        let localOffsetMin = localTZ.secondsFromGMT(for: now) / 60
        let isChinaTZ = (localTzID == "Asia/Shanghai" || localTzID == "Asia/Chongqing" || localTzID == "Asia/Urumqi" || localTzID == "Asia/Harbin")

        let langs = (UserDefaults.standard.array(forKey: "AppleLanguages") as? [String]) ?? Locale.preferredLanguages
        let primaryLang = (langs.first ?? "en").split(separator: "-").first.map { $0.lowercased() } ?? "en"

        let cc = (exitCountryCode ?? "").uppercased()
        let resolvedExitTZ: String?
        let isEstimated: Bool
        if let exact = exitExactTimezone, !exact.isEmpty {
            resolvedExitTZ = exact
            isEstimated = false
        } else if let fallback = RestrictedRegions.countryToRepresentativeTimezone[cc] {
            resolvedExitTZ = fallback
            isEstimated = true
        } else {
            resolvedExitTZ = nil
            isEstimated = false
        }

        var exitOffsetMin: Int?
        var tzMatched: Bool?
        if let tzName = resolvedExitTZ, let tz = TimeZone(identifier: tzName) {
            let off = tz.secondsFromGMT(for: now) / 60
            exitOffsetMin = off
            tzMatched = !isChinaTZ && abs(off - localOffsetMin) <= 60
        } else if isChinaTZ {
            tzMatched = false
        }

        let expectedLangs = RestrictedRegions.countryToAcceptedLanguages[cc] ?? []
        let langMatched: Bool? = expectedLangs.isEmpty ? nil : expectedLangs.contains(primaryLang)

        return DeviceConsistencyResult(
            localTimezone: localTzID,
            localUTCOffsetMinutes: localOffsetMin,
            exitTimezone: resolvedExitTZ,
            exitTimezoneIsEstimated: isEstimated,
            exitUTCOffsetMinutes: exitOffsetMin,
            timezoneMatched: tzMatched,
            isChinaMainlandTimezone: isChinaTZ,
            appleLanguages: Array(langs.prefix(4)),
            primaryLanguageCode: primaryLang,
            expectedRegionLanguages: expectedLangs,
            languageMatched: langMatched
        )
    }
}
