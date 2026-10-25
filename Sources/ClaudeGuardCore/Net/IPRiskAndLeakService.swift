import Foundation
import Network

public struct LiveNetworkProbeService: NetworkProbing {
    private let traceClient = DualStackProbeClient()

    public init() {}

    public func probeTrace(label: String, urlString: String, timeout: TimeInterval = 5.0) async -> TraceProbeResult {
        await traceClient.fetchTrace(label: label, urlString: urlString, timeout: timeout)
    }

    public func sampleExitRotation(urlString: String, sampleCount: Int, timeout: TimeInterval = 5.0) async -> [String] {
        await traceClient.sampleRotation(urlString: urlString, count: sampleCount, timeout: timeout)
    }

    public func fetchIPRisk(ip: String, timeout: TimeInterval = 8.0) async -> IPRiskSnapshot? {
        guard let encoded = ip.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed),
              let url = URL(string: "https://ip.net.coffee/api/iprisk/\(encoded)") else {
            return nil
        }
        guard let data = await fetchRawData(url: url, timeout: timeout) else { return nil }
        return Self.parseIPRiskJSON(data: data, fallbackIP: ip)
    }

    public static func parseIPRiskJSON(data: Data, fallbackIP: String) -> IPRiskSnapshot? {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        let asnVal: Int?
        if let n = obj["asn"] as? Int {
            asnVal = n
        } else if let s = obj["asn"] as? String {
            asnVal = Int(s.replacingOccurrences(of: "AS", with: ""))
        } else {
            asnVal = nil
        }

        let trustScore: Int?
        if let n = obj["trust_score"] as? Int {
            trustScore = n
        } else if let d = obj["trust_score"] as? Double {
            trustScore = Int(d.rounded())
        } else {
            trustScore = nil
        }

        return IPRiskSnapshot(
            ip: (obj["ip"] as? String) ?? fallbackIP,
            country: obj["country"] as? String,
            countryCode: (obj["countryCode"] as? String)?.uppercased(),
            region: obj["region"] as? String,
            city: obj["city"] as? String,
            asn: asnVal,
            asOrganization: obj["asOrganization"] as? String,
            trustScore: trustScore,
            isResidential: obj["isResidential"] as? Bool,
            isBroadcast: obj["isBroadcast"] as? Bool,
            isDatacenter: obj["is_datacenter"] as? Bool,
            isVPN: obj["is_vpn"] as? Bool,
            isProxy: obj["is_proxy"] as? Bool,
            isTor: obj["is_tor"] as? Bool,
            isCrawler: obj["is_crawler"] as? Bool,
            isAbuser: obj["is_abuser"] as? Bool,
            companyType: obj["company_type"] as? String,
            companyName: obj["company_name"] as? String,
            timezone: obj["timezone"] as? String
        )
    }

    public func fetchGeoIP(ip: String, timeout: TimeInterval = 5.0) async -> GeoIPSummary? {
        guard let encoded = ip.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed),
              let url = URL(string: "https://ip.net.coffee/api/geoip/\(encoded)") else {
            return nil
        }
        guard let data = await fetchRawData(url: url, timeout: timeout),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return GeoIPSummary(
            ip: ip,
            country: obj["country"] as? String,
            countryCode: (obj["country_code"] as? String)?.uppercased(),
            region: obj["region"] as? String,
            city: obj["city"] as? String,
            isp: obj["isp"] as? String
        )
    }

    public func fetchCNExitIP(timeout: TimeInterval = 4.5) async -> String? {
        let candidates = ["https://2026.ip138.com/", "https://my.ip.cn/"]
        for urlStr in candidates {
            guard let url = URL(string: urlStr),
                  let data = await fetchRawData(url: url, timeout: timeout),
                  let html = String(data: data, encoding: .utf8) else {
                continue
            }
            if let ip = Self.extractFirstIPv4(from: html) {
                return ip
            }
        }
        return nil
    }

    public static func extractFirstIPv4(from text: String) -> String? {
        let pattern = #"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        guard let match = regex.firstMatch(in: text, range: range),
              let swiftRange = Range(match.range, in: text) else {
            return nil
        }
        return String(text[swiftRange])
    }

    public func fetchClaudeServiceStatus(timeout: TimeInterval = 3.5) async -> String? {
        guard let url = URL(string: "https://ip.net.coffee/claude/status.json"),
              let data = await fetchRawData(url: url, timeout: timeout),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return (obj["overall_indicator"] as? String) ?? "none"
    }

    public func detectDNSLeak(claudeCountryCode: String?, timeout: TimeInterval = 5.0) async -> DNSLeakResult {
        let alphabet = Array("abcdefghijklmnopqrstuvwxyz0123456789")
        let token = String((0..<22).map { _ in alphabet.randomElement()! })

        // Trigger 2 authoritative DNS resolutions
        for round in 1...2 {
            let subURLStr = "https://\(token)-\(round).d.ip.net.coffee/pixel.gif?_=\(Int(Date().timeIntervalSince1970 * 1000))"
            if let u = URL(string: subURLStr) {
                _ = await fetchRawData(url: u, timeout: 2.0)
            }
        }

        try? await Task.sleep(for: .milliseconds(1200))

        var servers: [String] = []
        if let resultURL = URL(string: "https://ip.net.coffee/api/dns/result/\(token)") {
            for attempt in 0..<2 {
                if let data = await fetchRawData(url: resultURL, timeout: 3.0),
                   let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let arr = obj["dns_servers"] as? [String], !arr.isEmpty {
                    servers = arr
                    break
                }
                if attempt == 0 {
                    try? await Task.sleep(for: .milliseconds(1100))
                }
            }
        }

        if servers.isEmpty {
            return DNSLeakResult(checked: true, encryptedOrUnexposed: true, hasCNLeak: false, resolverIPs: [])
        }

        let claudeIsCN = (claudeCountryCode?.uppercased() == "CN")
        var primaryGeo: GeoIPSummary?
        var leakedCN = false

        for ip in servers.prefix(4) {
            if let geo = await fetchGeoIP(ip: ip, timeout: 3.0) {
                if primaryGeo == nil { primaryGeo = geo }
                if geo.countryCode?.uppercased() == "CN" && !claudeIsCN {
                    leakedCN = true
                    primaryGeo = geo
                    break
                }
            }
        }

        return DNSLeakResult(
            checked: true,
            encryptedOrUnexposed: false,
            hasCNLeak: leakedCN,
            resolverIPs: servers,
            primaryResolverGeo: primaryGeo
        )
    }

    public func detectUDPLeak(claudeExitIP: String?, timeout: TimeInterval = 3.5) async -> UDPLeakResult {
        let stunTargets: [(host: String, port: UInt16)] = [
            ("stun.cloudflare.com", 3478),
            ("stun.l.google.com", 19302)
        ]

        var discoveredPublic: [String] = []
        await withTaskGroup(of: String?.self) { group in
            for target in stunTargets {
                group.addTask {
                    await STUNProbe.queryMappedAddress(host: target.host, port: target.port, timeout: timeout)
                }
            }
            for await maybeIP in group {
                if let ip = maybeIP, Self.isPublicIPv4OrIPv6(ip), !discoveredPublic.contains(ip) {
                    discoveredPublic.append(ip)
                }
            }
        }

        if discoveredPublic.isEmpty {
            return UDPLeakResult(checked: true, publicUDPIPs: [], matchesClaudeExit: true)
        }

        let leaked: String?
        if let expected = claudeExitIP, !expected.isEmpty {
            leaked = discoveredPublic.first(where: { $0 != expected })
        } else {
            leaked = nil
        }

        var leakedGeo: GeoIPSummary?
        if let lip = leaked {
            leakedGeo = await fetchGeoIP(ip: lip, timeout: 3.0)
        } else if let first = discoveredPublic.first {
            leakedGeo = await fetchGeoIP(ip: first, timeout: 3.0)
        }

        return UDPLeakResult(
            checked: true,
            publicUDPIPs: discoveredPublic,
            matchesClaudeExit: leaked == nil,
            leakedIP: leaked,
            leakedGeo: leakedGeo
        )
    }

    private static func isPublicIPv4OrIPv6(_ ip: String) -> Bool {
        if ip.contains(":") {
            let lower = ip.lowercased()
            return (lower.hasPrefix("2") || lower.hasPrefix("3")) && !lower.hasPrefix("2001:db8:")
        }
        if ip.hasPrefix("10.") || ip.hasPrefix("127.") || ip.hasPrefix("192.168.") ||
            ip.hasPrefix("198.18.") || ip.hasPrefix("198.19.") || ip.hasPrefix("100.64.") || ip.hasPrefix("0.") {
            return false
        }
        if ip.hasPrefix("172.") {
            let parts = ip.split(separator: ".")
            if parts.count >= 2, let second = Int(parts[1]), (16...31).contains(second) {
                return false
            }
        }
        return true
    }

    private func fetchRawData(url: URL, timeout: TimeInterval) async -> Data? {
        let session = DualStackProbeClient.makeIsolatedEphemeralSession(timeout: timeout)
        defer { session.finishTasksAndInvalidate() }
        guard let (data, resp) = try? await session.data(from: url),
              let http = resp as? HTTPURLResponse,
              (200...299).contains(http.statusCode) else {
            return nil
        }
        return data
    }
}

// MARK: - Pure Swift RFC 5389 STUN Client & Codec

public enum STUNProbe {
    public static let magicCookie: UInt32 = 0x2112A442

    public static func buildBindingRequest(transactionID: [UInt8]) -> Data {
        precondition(transactionID.count == 12)
        var packet = Data(capacity: 20)
        // Binding Request 0x0001, Message Length 0x0000
        packet.append(contentsOf: [0x00, 0x01, 0x00, 0x00])
        // Magic Cookie 0x2112A442
        packet.append(contentsOf: [0x21, 0x12, 0xA4, 0x42])
        packet.append(contentsOf: transactionID)
        return packet
    }

    public static func parseBindingResponse(_ data: Data, transactionID: [UInt8]) -> String? {
        let bytes = [UInt8](data)
        guard bytes.count >= 20, transactionID.count == 12 else { return nil }
        // Binding Success Response is 0x0101
        guard bytes[0] == 0x01 && bytes[1] == 0x01 else { return nil }
        let msgLen = (Int(bytes[2]) << 8) | Int(bytes[3])
        guard bytes.count >= min(20 + msgLen, 20) else { return nil }
        // Verify Magic Cookie
        guard bytes[4] == 0x21 && bytes[5] == 0x12 && bytes[6] == 0xA4 && bytes[7] == 0x42 else { return nil }

        let cookieBytes: [UInt8] = [0x21, 0x12, 0xA4, 0x42]
        var offset = 20
        var fallbackMapped: String?

        while offset + 4 <= bytes.count {
            let attrType = (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
            let attrLen = (Int(bytes[offset + 2]) << 8) | Int(bytes[offset + 3])
            let valStart = offset + 4
            guard valStart + attrLen <= bytes.count else { break }

            // XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
            if (attrType == 0x0020 || attrType == 0x0001) && attrLen >= 8 {
                let family = bytes[valStart + 1]
                let isXor = (attrType == 0x0020)
                if family == 0x01 {
                    // IPv4 (4 bytes at valStart + 4)
                    var ipBytes = Array(bytes[(valStart + 4)..<(valStart + 8)])
                    if isXor {
                        for i in 0..<4 { ipBytes[i] ^= cookieBytes[i] }
                    }
                    let ipStr = ipBytes.map(String.init).joined(separator: ".")
                    if isXor { return ipStr }
                    fallbackMapped = ipStr
                } else if family == 0x02 && attrLen >= 20 {
                    // IPv6 (16 bytes at valStart + 4)
                    var ipBytes = Array(bytes[(valStart + 4)..<(valStart + 20)])
                    if isXor {
                        let mask = cookieBytes + transactionID
                        for i in 0..<16 { ipBytes[i] ^= mask[i] }
                    }
                    var groups: [String] = []
                    for g in stride(from: 0, to: 16, by: 2) {
                        let word = (UInt16(ipBytes[g]) << 8) | UInt16(ipBytes[g + 1])
                        groups.append(String(word, radix: 16))
                    }
                    let ip6 = groups.joined(separator: ":")
                    if isXor { return ip6 }
                    fallbackMapped = ip6
                }
            }
            // STUN attributes are padded to 4-byte boundaries
            let paddedLen = (attrLen + 3) & ~3
            offset = valStart + paddedLen
        }
        return fallbackMapped
    }

    public static func queryMappedAddress(host: String, port: UInt16, timeout: TimeInterval) async -> String? {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return nil }
        let txID = (0..<12).map { _ in UInt8.random(in: 0...255) }
        let requestData = buildBindingRequest(transactionID: txID)

        return await withCheckedContinuation { continuation in
            final class ResumeGuard: @unchecked Sendable {
                private let lock = NSLock()
                private var resumed = false
                func tryResume(_ block: () -> Void) {
                    lock.lock()
                    defer { lock.unlock() }
                    guard !resumed else { return }
                    resumed = true
                    block()
                }
            }

            let guardBox = ResumeGuard()
            let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .udp)
            let queue = DispatchQueue(label: "com.claudeguard.stun.\(UUID().uuidString)")

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.send(content: requestData, completion: .contentProcessed { sendErr in
                        if sendErr != nil {
                            guardBox.tryResume {
                                connection.cancel()
                                continuation.resume(returning: nil)
                            }
                            return
                        }
                        connection.receiveMessage { data, _, _, _ in
                            let parsed = data.flatMap { parseBindingResponse($0, transactionID: txID) }
                            guardBox.tryResume {
                                connection.cancel()
                                continuation.resume(returning: parsed)
                            }
                        }
                    })
                case .failed, .cancelled:
                    guardBox.tryResume {
                        connection.cancel()
                        continuation.resume(returning: nil)
                    }
                default:
                    break
                }
            }

            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                guardBox.tryResume {
                    connection.cancel()
                    continuation.resume(returning: nil)
                }
            }
        }
    }
}
