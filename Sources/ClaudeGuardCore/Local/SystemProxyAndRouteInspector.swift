import Foundation
import AppKit
import CFNetwork
import SystemConfiguration

public protocol NetworkEnvironmentInspecting: Sendable {
    func inspectProxySettings() -> ProxySettingsSnapshot
    func inspectKernelRoutes() -> KernelRouteSnapshot
    func scanInstalledProxyClients() -> [ProxyClientApp]
    func classifyTransportMode(proxy: ProxySettingsSnapshot, routes: KernelRouteSnapshot) -> TransportMode
}

public struct SystemProxyAndRouteInspector: NetworkEnvironmentInspecting {
    private let shell: any ShellCommandRunning

    public init(shell: any ShellCommandRunning = LiveShellRunner()) {
        self.shell = shell
    }

    public func inspectProxySettings() -> ProxySettingsSnapshot {
        guard let cfProxies = SCDynamicStoreCopyProxies(nil) else {
            // Fallback to scutil --proxy parsing if SCDynamicStore unavailable
            let res = shell.run(executable: "/usr/sbin/scutil", arguments: ["--proxy"], timeoutSeconds: 2.0)
            return Self.parseScutilProxyOutput(res.stdout)
        }
        let dict = cfProxies as NSDictionary
        return Self.extractProxySettings(from: dict, rawCFDict: cfProxies)
    }

    public static func extractProxySettings(from dict: NSDictionary, rawCFDict: CFDictionary? = nil) -> ProxySettingsSnapshot {
        let httpEnable = (dict["HTTPEnable"] as? NSNumber)?.intValue == 1
        let httpHost = dict["HTTPProxy"] as? String
        let httpPort = (dict["HTTPPort"] as? NSNumber)?.intValue

        let httpsEnable = (dict["HTTPSEnable"] as? NSNumber)?.intValue == 1
        let httpsHost = dict["HTTPSProxy"] as? String
        let httpsPort = (dict["HTTPSPort"] as? NSNumber)?.intValue

        let socksEnable = (dict["SOCKSEnable"] as? NSNumber)?.intValue == 1
        let socksHost = dict["SOCKSProxy"] as? String
        let socksPort = (dict["SOCKSPort"] as? NSNumber)?.intValue

        let pacEnable = (dict["ProxyAutoConfigEnable"] as? NSNumber)?.intValue == 1
        let pacURL = dict["ProxyAutoConfigURLString"] as? String
        let exceptions = (dict["ExceptionsList"] as? [String]) ?? []

        // Evaluate per-domain consistency via CFNetworkCopyProxiesForURL when proxy dict is available
        var bypassed: [String] = []
        var consistent = true
        let anySystemProxyOn = httpEnable || httpsEnable || socksEnable || pacEnable

        if anySystemProxyOn, let cfDict = rawCFDict {
            var baselineSignature: String?
            for domain in RestrictedRegions.criticalClaudeDomains {
                guard let url = URL(string: "https://\(domain)/") else { continue }
                let proxiesArray = CFNetworkCopyProxiesForURL(url as CFURL, cfDict).takeRetainedValue() as NSArray
                let sig = Self.proxySignature(from: proxiesArray)
                if sig == "DIRECT" {
                    bypassed.append(domain)
                }
                if let base = baselineSignature {
                    if base != sig {
                        consistent = false
                    }
                } else {
                    baselineSignature = sig
                }
            }
        } else if anySystemProxyOn {
            // Check simple suffix match against ExceptionsList
            for domain in RestrictedRegions.criticalClaudeDomains {
                if Self.matchesBypassList(domain: domain, exceptions: exceptions) {
                    bypassed.append(domain)
                    consistent = false
                }
            }
        }

        return ProxySettingsSnapshot(
            httpEnabled: httpEnable,
            httpHost: httpHost,
            httpPort: httpPort,
            httpsEnabled: httpsEnable,
            httpsHost: httpsHost,
            httpsPort: httpsPort,
            socksEnabled: socksEnable,
            socksHost: socksHost,
            socksPort: socksPort,
            pacEnabled: pacEnable,
            pacURL: pacURL,
            exceptionsList: exceptions,
            domainRoutingConsistent: consistent && bypassed.isEmpty,
            bypassedCriticalDomains: bypassed
        )
    }

    private static func proxySignature(from proxiesArray: NSArray) -> String {
        guard let first = proxiesArray.firstObject as? NSDictionary,
              let type = first[kCFProxyTypeKey as String] as? String else {
            return "DIRECT"
        }
        if type == (kCFProxyTypeNone as String) {
            return "DIRECT"
        }
        let host = (first[kCFProxyHostNameKey as String] as? String) ?? ""
        let port = (first[kCFProxyPortNumberKey as String] as? NSNumber)?.intValue ?? 0
        let pac = (first[kCFProxyAutoConfigurationURLKey as String] as? URL)?.absoluteString ?? ""
        return "\(type):\(host):\(port):\(pac)"
    }

    public static func matchesBypassList(domain: String, exceptions: [String]) -> Bool {
        let lower = domain.lowercased()
        for rawPattern in exceptions {
            let pat = rawPattern.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if pat.isEmpty { continue }
            let clean = pat.hasPrefix("*.") ? String(pat.dropFirst(2)) : pat
            if lower == clean || lower.hasSuffix(".\(clean)") {
                return true
            }
        }
        return false
    }

    public static func parseScutilProxyOutput(_ text: String) -> ProxySettingsSnapshot {
        var kv: [String: String] = [:]
        var exceptions: [String] = []
        var inExceptions = false

        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("ExceptionsList :") {
                inExceptions = true
                continue
            }
            if inExceptions {
                if line == "}" {
                    inExceptions = false
                    continue
                }
                if let colonIdx = line.firstIndex(of: ":") {
                    let val = line[line.index(after: colonIdx)...].trimmingCharacters(in: .whitespaces)
                    if !val.isEmpty { exceptions.append(val) }
                }
                continue
            }
            if let colonIdx = line.firstIndex(of: ":") {
                let key = line[..<colonIdx].trimmingCharacters(in: .whitespaces)
                let val = line[line.index(after: colonIdx)...].trimmingCharacters(in: .whitespaces)
                kv[key] = val
            }
        }

        let dict = NSMutableDictionary()
        dict["HTTPEnable"] = Int(kv["HTTPEnable"] ?? "0") ?? 0
        if let h = kv["HTTPProxy"] { dict["HTTPProxy"] = h }
        if let p = Int(kv["HTTPPort"] ?? "") { dict["HTTPPort"] = p }

        dict["HTTPSEnable"] = Int(kv["HTTPSEnable"] ?? "0") ?? 0
        if let h = kv["HTTPSProxy"] { dict["HTTPSProxy"] = h }
        if let p = Int(kv["HTTPSPort"] ?? "") { dict["HTTPSPort"] = p }

        dict["SOCKSEnable"] = Int(kv["SOCKSEnable"] ?? "0") ?? 0
        if let h = kv["SOCKSProxy"] { dict["SOCKSProxy"] = h }
        if let p = Int(kv["SOCKSPort"] ?? "") { dict["SOCKSPort"] = p }

        dict["ProxyAutoConfigEnable"] = Int(kv["ProxyAutoConfigEnable"] ?? "0") ?? 0
        if let u = kv["ProxyAutoConfigURLString"] { dict["ProxyAutoConfigURLString"] = u }
        dict["ExceptionsList"] = exceptions

        return extractProxySettings(from: dict, rawCFDict: nil)
    }

    public func inspectKernelRoutes() -> KernelRouteSnapshot {
        let defaultRoute = queryRoute(arguments: ["-n", "get", "default"], targetLabel: "default")
        let cfRoute = queryRoute(arguments: ["-n", "get", "1.1.1.1"], targetLabel: "1.1.1.1")
        let anthropicV4Route = queryRoute(arguments: ["-n", "get", "160.79.104.1"], targetLabel: "160.79.104.1")
        let anthropicV6Route = queryRoute(arguments: ["-n", "get", "-inet6", "2607:6bc0::1"], targetLabel: "2607:6bc0::1")

        let ifconfigOut = shell.run(executable: "/sbin/ifconfig", arguments: [], timeoutSeconds: 2.0).stdout
        let publicV6 = Self.parsePhysicalPublicIPv6(from: ifconfigOut)

        return KernelRouteSnapshot(
            defaultIPv4: defaultRoute,
            cloudflareIPv4: cfRoute,
            anthropicIPv4: anthropicV4Route,
            anthropicIPv6: anthropicV6Route,
            publicIPv6AddressesOnPhysical: publicV6
        )
    }

    private func queryRoute(arguments: [String], targetLabel: String) -> RouteTargetCheck {
        let res = shell.run(executable: "/sbin/route", arguments: arguments, timeoutSeconds: 2.0)
        return Self.parseRouteGetOutput(res.stdout, target: targetLabel)
    }

    public static func parseRouteGetOutput(_ output: String, target: String) -> RouteTargetCheck {
        var iface: String?
        var gateway: String?
        for rawLine in output.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("interface:") {
                iface = line.replacingOccurrences(of: "interface:", with: "").trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("gateway:") {
                gateway = line.replacingOccurrences(of: "gateway:", with: "").trimmingCharacters(in: .whitespaces)
            }
        }
        let isTun: Bool
        if let name = iface?.lowercased() {
            isTun = name.hasPrefix("utun") || name.hasPrefix("ppp") || name.hasPrefix("ipsec") || name.hasPrefix("tun")
        } else {
            isTun = false
        }
        return RouteTargetCheck(target: target, interfaceName: iface, gateway: gateway, isTunInterface: isTun)
    }

    public static func parsePhysicalPublicIPv6(from ifconfigOutput: String) -> [String] {
        var results: [String] = []
        var currentInterface = ""

        for rawLine in ifconfigOutput.split(whereSeparator: \.isNewline) {
            let line = String(rawLine)
            if !line.hasPrefix("\t") && !line.hasPrefix(" "), let colon = line.firstIndex(of: ":") {
                currentInterface = String(line[..<colon])
                continue
            }
            // Only inspect physical interfaces such as en0, en1, en2...
            guard currentInterface.hasPrefix("en") else { continue }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("inet6 ") else { continue }
            let tokens = trimmed.split(separator: " ")
            guard tokens.count >= 2 else { continue }
            let addr = String(tokens[1]).split(separator: "%").first.map(String.init) ?? ""
            let lower = addr.lowercased()
            // Global unicast IPv6 starts with 2 or 3 (2000::/3), excluding link-local fe80, ULA fc/fd, loopback ::1
            if (lower.hasPrefix("2") || lower.hasPrefix("3")) && !lower.hasPrefix("2001:db8:") {
                if !results.contains(addr) {
                    results.append(addr)
                }
            }
        }
        return results
    }

    public func classifyTransportMode(proxy: ProxySettingsSnapshot, routes: KernelRouteSnapshot) -> TransportMode {
        let tunOn = routes.isTunActiveForClaude
        if tunOn && (proxy.hasExplicitHTTPProxy || proxy.pacEnabled || proxy.socksEnabled) {
            return .tunAndSystemProxy
        }
        if tunOn {
            return .tunOnly
        }
        if proxy.hasExplicitHTTPProxy {
            return .systemProxyOnly
        }
        if proxy.pacEnabled {
            return .pacAutoProxy
        }
        if proxy.socksEnabled {
            return .socksOnly
        }
        return .directNoProxy
    }

    public func scanInstalledProxyClients() -> [ProxyClientApp] {
        let knownCandidates: [(name: String, bundleID: String, paths: [String])] = [
            ("Clash Verge", "io.github.clash-verge-rev.clash-verge-rev", ["/Applications/Clash Verge.app"]),
            ("Surge", "com.nssurge.surge-mac", ["/Applications/Surge.app"]),
            ("Mihomo Party", "party.mihomo.app", ["/Applications/Mihomo Party.app"]),
            ("FlClash", "com.follow.clash", ["/Applications/FlClash.app"]),
            ("ClashX Meta", "com.metacubex.ClashX.meta", ["/Applications/ClashX Meta.app", "/Applications/ClashX.app"]),
            ("Sing-box", "io.nekohasekai.sfavt", ["/Applications/SFM.app", "/Applications/sing-box.app"]),
            ("VPN Cat", "com.vpncat.mac", ["/Applications/VPN cat.app", "/Applications/VPNCat.app"])
        ]

        let runningApps = NSWorkspace.shared.runningApplications
        let runningBundleIDs = Set(runningApps.compactMap(\.bundleIdentifier))
        let runningNames = Set(runningApps.compactMap { $0.localizedName?.lowercased() })

        var discovered: [ProxyClientApp] = []
        let fm = FileManager.default

        for candidate in knownCandidates {
            if let existingPath = candidate.paths.first(where: { fm.fileExists(atPath: $0) }) {
                let bundle = Bundle(path: existingPath)
                let bid = bundle?.bundleIdentifier ?? candidate.bundleID
                let running = runningBundleIDs.contains(bid)
                    || runningBundleIDs.contains(candidate.bundleID)
                    || runningNames.contains(candidate.name.lowercased())
                discovered.append(ProxyClientApp(name: candidate.name, bundleID: bid, path: existingPath, isRunning: running))
            }
        }
        return discovered
    }
}
