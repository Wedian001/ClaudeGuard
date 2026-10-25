import Foundation

public protocol NetworkProbing: Sendable {
    func probeTrace(label: String, urlString: String, timeout: TimeInterval) async -> TraceProbeResult
    func sampleExitRotation(urlString: String, sampleCount: Int, timeout: TimeInterval) async -> [String]
    func fetchIPRisk(ip: String, timeout: TimeInterval) async -> IPRiskSnapshot?
    func fetchGeoIP(ip: String, timeout: TimeInterval) async -> GeoIPSummary?
    func fetchCNExitIP(timeout: TimeInterval) async -> String?
    func fetchClaudeServiceStatus(timeout: TimeInterval) async -> String?
    func detectDNSLeak(claudeCountryCode: String?, timeout: TimeInterval) async -> DNSLeakResult
    func detectUDPLeak(claudeExitIP: String?, timeout: TimeInterval) async -> UDPLeakResult
}

public struct DualStackProbeClient: Sendable {
    public init() {}

    /// Creates a fresh zero-cookie, zero-cache ephemeral URLSession that honors macOS system proxy/PAC/SOCKS5
    /// identically to Chromium/Electron, without reusing TCP connections across sessions.
    public static func makeIsolatedEphemeralSession(timeout: TimeInterval) -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout + 1.0
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.httpCookieAcceptPolicy = .never
        config.httpShouldSetCookies = false
        config.urlCredentialStorage = nil
        config.httpMaximumConnectionsPerHost = 1
        config.httpAdditionalHeaders = [
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "Connection": "close",
            "Cache-Control": "no-cache, no-store"
        ]
        return URLSession(configuration: config)
    }

    public func fetchTrace(label: String, urlString: String, timeout: TimeInterval = 5.0) async -> TraceProbeResult {
        guard let url = URL(string: urlString) else {
            return TraceProbeResult(label: label, url: urlString, error: "Invalid URL")
        }
        let session = Self.makeIsolatedEphemeralSession(timeout: timeout)
        defer { session.finishTasksAndInvalidate() }

        let start = ContinuousClock.now
        do {
            let (data, response) = try await session.data(from: url)
            let elapsed = start.duration(to: ContinuousClock.now)
            let ms = Int(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000)

            if let httpResp = response as? HTTPURLResponse, !(200...299).contains(httpResp.statusCode) {
                return TraceProbeResult(
                    label: label,
                    url: urlString,
                    latencyMs: ms,
                    error: "HTTP \(httpResp.statusCode)"
                )
            }
            let text = String(data: data, encoding: .utf8) ?? ""
            return Self.parseCloudflareTrace(text, label: label, url: urlString, latencyMs: ms)
        } catch {
            let elapsed = start.duration(to: ContinuousClock.now)
            let ms = Int(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000)
            return TraceProbeResult(
                label: label,
                url: urlString,
                latencyMs: ms,
                error: error.localizedDescription
            )
        }
    }

    public static func parseCloudflareTrace(
        _ rawText: String,
        label: String,
        url: String,
        latencyMs: Int
    ) -> TraceProbeResult {
        var map: [String: String] = [:]
        for line in rawText.split(whereSeparator: \.isNewline) {
            if let eq = line.firstIndex(of: "=") {
                let k = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
                let v = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                map[k] = v
            }
        }
        let ip = map["ip"]
        let isV6 = ip?.contains(":") ?? false
        if ip == nil {
            return TraceProbeResult(
                label: label,
                url: url,
                latencyMs: latencyMs,
                error: "Invalid trace response"
            )
        }
        return TraceProbeResult(
            label: label,
            url: url,
            ip: ip,
            loc: map["loc"]?.uppercased(),
            colo: map["colo"],
            httpVersion: map["http"],
            tlsVersion: map["tls"],
            latencyMs: latencyMs,
            isIPv6: isV6,
            error: nil
        )
    }

    /// Samples exit IP across N brand-new TCP connections concurrently with slight stagger
    /// so per-connection airport IP rotation pools are reliably detected.
    public func sampleRotation(urlString: String, count: Int, timeout: TimeInterval = 5.0) async -> [String] {
        guard count > 0 else { return [] }
        return await withTaskGroup(of: String?.self) { group in
            for idx in 0..<count {
                group.addTask {
                    if idx > 0 {
                        try? await Task.sleep(for: .milliseconds(55 * idx))
                    }
                    let res = await self.fetchTrace(label: "sample-\(idx)", urlString: urlString, timeout: timeout)
                    return res.ip
                }
            }
            var unique: [String] = []
            for await maybeIP in group {
                if let ip = maybeIP, !unique.contains(ip) {
                    unique.append(ip)
                }
            }
            return unique
        }
    }
}
