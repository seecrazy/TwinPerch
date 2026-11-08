import Foundation

/// IMAP4rev1 子集客户端（docs/03 §5）：
/// AUTHENTICATE PLAIN / CREATE / SELECT / UID SEARCH UNSEEN / UID FETCH (BODY.PEEK[]) /
/// UID STORE +FLAGS.SILENT \Deleted / EXPUNGE / IDLE / LOGOUT。
/// 面向 MailConnection 抽象，可脚本化测试；实连验证（QQ/163 兼容性）属 Phase 0 人工项。

public enum IMAPError: Error, Equatable {
    case serverError(String)     // tagged NO / BAD
    case connectionClosed
    case malformedResponse
    case authFailed
    case timeout
}

public final class IMAPClient: @unchecked Sendable {
    private let conn: MailConnection
    private let lock = NSLock()
    private var tagCounter = 0
    private var currentTag = "a0"
    public private(set) var folder: String?

    public init(connection: MailConnection) {
        self.conn = connection
    }

    public func connect(host: String, port: Int, tls: Bool) async throws {
        try await conn.connect(host: host, port: port, tls: tls)
    }

    /// 连接后的服务器问候行（`* OK ...`）
    @discardableResult
    public func readGreeting() async throws -> String {
        let line = try await conn.readLine()
        guard line.hasPrefix("*") else { throw IMAPError.malformedResponse }
        return line
    }

    // MARK: - 命令

    public func login(user: String, password: String) async throws {
        // 经典两步式：先发 AUTHENTICATE PLAIN，服务器回 "+" 后再发凭据行
        let sasl = Data("\u{0}\(user)\u{0}\(password)".utf8).base64EncodedString()
        let tag = try await beginCommand("AUTHENTICATE PLAIN")
        var line = try await conn.readLine()
        if line.hasPrefix("+") {
            try await conn.sendLine(sasl)
            line = try await conn.readLine()
        }
        guard line.hasPrefix("\(tag) "), line.uppercased().contains("OK") else {
            throw IMAPError.authFailed
        }
    }

    /// ALREADYEXISTS 视为成功
    public func ensureFolder(_ name: String) async throws {
        let reply = try await sendCommand("CREATE \(quoted(name))")
        let upper = reply.uppercased()
        guard upper.contains("OK") || upper.contains("ALREADYEXISTS") else {
            throw IMAPError.serverError(reply)
        }
    }

    public func selectFolder(_ name: String) async throws {
        let reply = try await sendCommand("SELECT \(quoted(name))")
        guard reply.uppercased().contains("OK") else { throw IMAPError.serverError(reply) }
        folder = name
    }

    /// UID SEARCH UNSEEN → 未读 UID 列表（升序）
    public func searchUnseen() async throws -> [UInt32] {
        let (untagged, _) = try await sendCommandCollectingUntagged("UID SEARCH UNSEEN")
        for line in untagged {
            let parts = line.split(separator: " ")
            if parts.count >= 2, parts[0] == "*", parts[1].uppercased() == "SEARCH" {
                return parts.dropFirst(2).compactMap { UInt32($0) }
            }
        }
        return []
    }

    /// UID FETCH：返回 (uid, MIME 原始字节)。处理 literal {N}。
    public func fetchMessage(uid: UInt32) async throws -> (uid: UInt32, data: Data) {
        let tag = try await beginCommand("UID FETCH \(uid) (BODY.PEEK[])")
        var data = Data()
        var seenUID: UInt32?
        while true {
            let line = try await conn.readLine()
            if line.hasPrefix("\(tag) ") {
                guard line.uppercased().contains("OK") else { throw IMAPError.serverError(line) }
                break
            }
            // literal：行尾 {N}，其后紧跟 N 字节原始数据
            if let brace = line.range(of: #"\{(\d+)\}$"#, options: .regularExpression) {
                let numStr = line[brace].dropFirst().dropLast()
                guard let n = Int(numStr) else { throw IMAPError.malformedResponse }
                data.append(try await conn.readBytes(n))
            }
            if let uidRange = line.range(of: #"UID (\d+)"#, options: .regularExpression) {
                let uidStr = line[uidRange].split(separator: " ").last ?? "0"
                seenUID = UInt32(uidStr)
            }
        }
        guard let resultUID = seenUID else { throw IMAPError.malformedResponse }
        return (resultUID, data)
    }

    public func markDeleted(uid: UInt32) async throws {
        _ = try await sendCommand("UID STORE \(uid) +FLAGS.SILENT (\\Deleted)")
    }

    public func expunge() async throws {
        _ = try await sendCommand("EXPUNGE")
    }

    /// IDLE：等待新邮件（EXISTS）或超时。到期主动 DONE 退出（服务器约 29 分钟踢空闲，客户端 ≤ 25 分钟）。
    public func idle(timeout: TimeInterval = 20) async throws -> Bool {
        let tag = try await beginCommand("IDLE")
        var line = try await conn.readLine()
        guard line.hasPrefix("+") else {
            if line.hasPrefix("\(tag) ") { return false }   // 服务器拒绝 IDLE
            throw IMAPError.malformedResponse
        }
        var gotExists = false
        while true {
            do {
                line = try await withTimeout(seconds: timeout) {
                    try await self.conn.readLine()
                }
            } catch let e as IMAPError {
                throw e
            } catch {
                // 底层连接错误统一归一化，调用方按断线处理
                throw IMAPError.connectionClosed
            }
            if line.hasSuffix("EXISTS") { gotExists = true }
            if line.uppercased().contains("BYE") {
                try await conn.sendLine("DONE")
                throw IMAPError.connectionClosed
            }
            if gotExists { break }
        }
        try await conn.sendLine("DONE")
        while true {
            let done = try await conn.readLine()
            if done.hasPrefix("\(tag) ") { break }
        }
        return gotExists
    }

    public func logout() async throws {
        _ = try? await sendCommand("LOGOUT")
        await conn.close()
    }

    // MARK: - 协议底层

    private func beginCommand(_ command: String) async throws -> String {
        lock.lock()
        tagCounter += 1
        currentTag = "a\(tagCounter)"
        let t = currentTag
        lock.unlock()
        try await conn.sendLine("\(t) \(command)")
        return t
    }

    /// 发送命令并等待本命令的 tagged 完成行（沿途 untagged 行丢弃）
    @discardableResult
    private func sendCommand(_ command: String) async throws -> String {
        let (_, taggedLine) = try await sendCommandCollectingUntagged(command)
        return taggedLine
    }

    private func sendCommandCollectingUntagged(_ command: String) async throws -> ([String], String) {
        let t = try await beginCommand(command)
        var untagged: [String] = []
        while true {
            let line = try await conn.readLine()
            if line.hasPrefix("\(t) ") {
                return (untagged, line)
            }
            untagged.append(line)
        }
    }

    private func quoted(_ s: String) -> String {
        "\"\(s)\""
    }
}

/// 轻量超时：Task 竞速（按行超时的真语义——底层 socket 超时——属 Phase 0 调优项）
func withTimeout<T: Sendable>(seconds: TimeInterval, _ op: @escaping @Sendable () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await op() }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(max(seconds, 0.05) * 1_000_000_000))
            throw IMAPError.timeout
        }
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}
