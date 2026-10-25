import Foundation

public struct ShellCommandResult: Sendable, Equatable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String

    public var succeeded: Bool { exitCode == 0 }

    public init(exitCode: Int32, stdout: String, stderr: String) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}

public protocol ShellCommandRunning: Sendable {
    func run(executable: String, arguments: [String], timeoutSeconds: TimeInterval) -> ShellCommandResult
}

public struct LiveShellRunner: ShellCommandRunning {
    public init() {}

    public func run(
        executable: String,
        arguments: [String],
        timeoutSeconds: TimeInterval = 4.0
    ) -> ShellCommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        var env = ProcessInfo.processInfo.environment
        env["LC_ALL"] = "C"
        process.environment = env

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        final class DataBox: @unchecked Sendable {
            var data = Data()
        }
        let outBox = DataBox()
        let errBox = DataBox()

        let readGroup = DispatchGroup()
        readGroup.enter()
        DispatchQueue.global(qos: .utility).async {
            outBox.data = outPipe.fileHandleForReading.readDataToEndOfFile()
            readGroup.leave()
        }
        readGroup.enter()
        DispatchQueue.global(qos: .utility).async {
            errBox.data = errPipe.fileHandleForReading.readDataToEndOfFile()
            readGroup.leave()
        }

        do {
            try process.run()
        } catch {
            return ShellCommandResult(exitCode: -1, stdout: "", stderr: error.localizedDescription)
        }

        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        if process.isRunning {
            process.terminate()
            kill(process.processIdentifier, SIGKILL)
            _ = readGroup.wait(timeout: .now() + 0.5)
            return ShellCommandResult(exitCode: -2, stdout: "", stderr: "Command timed out")
        }

        process.waitUntilExit()
        _ = readGroup.wait(timeout: .now() + 1.0)

        let stdoutStr = String(data: outBox.data, encoding: .utf8) ?? ""
        let stderrStr = String(data: errBox.data, encoding: .utf8) ?? ""
        return ShellCommandResult(exitCode: process.terminationStatus, stdout: stdoutStr, stderr: stderrStr)
    }
}
