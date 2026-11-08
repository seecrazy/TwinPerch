import Foundation

/// SMTP 客户端子集：EHLO / AUTH PLAIN / MAIL FROM / RCPT TO / DATA（含点填充）/ QUIT。
/// 465 直连 TLS；587 STARTTLS 属 Phase 0 实连调优项（QQ/163 默认 465）。

public enum SMTPError: Error, Equatable {
    case badReply(String)
    case authFailed
    case relayDenied(String)
}

public final class SMTPClient: @unchecked Sendable {
    private let conn: MailConnection

    public init(connection: MailConnection) {
        self.conn = connection
    }

    /// 完整发信流程。`data` 为已编码的 MIME 字节（CRLF 行结尾由调用方保证，见 MIME.encode）。
    public func send(from: String, to: String, authUser: String, authPassword: String,
                     data: Data) async throws {
        // 服务器问候
        let greeting = try await conn.readLine()
        guard greeting.hasPrefix("220") else { throw SMTPError.badReply(greeting) }

        try await ehlo()
        // AUTH PLAIN 单行
        let sasl = Data("\u{0}\(authUser)\u{0}\(authPassword)".utf8).base64EncodedString()
        let authReply = try await expectAny(["235", "334"], command: "AUTH PLAIN \(sasl)")
        if authReply.hasPrefix("334") {
            // 两步式：续行后发凭据
            try await expect("235", command: sasl)
        }

        try await expect("250", command: "MAIL FROM:<\(from)>")
        try await expect("250", command: "RCPT TO:<\(to)>")
        try await expect("354", command: "DATA")

        // 点填充 + CRLF 收尾
        try await conn.sendRaw(Self.dotStuffed(data))
        try await expect("250", command: ".")
        _ = try? await expect("221", command: "QUIT")
        await conn.close()
    }

    /// RFC 5321 §4.5.2：行首为 "." 的行前再加一个 "."
    static func dotStuffed(_ data: Data) -> Data {
        let crlf = Data("\r\n".utf8)
        var out = data
        // 保证以 CRLF 结束
        let bytes = [UInt8](out)
        if bytes.count < 2 || bytes[bytes.count - 2] != UInt8(ascii: "\r") || bytes[bytes.count - 1] != UInt8(ascii: "\n") {
            out.append(crlf)
        }
        var lines = splitLines(out)
        lines = lines.map { line in
            (line.first == UInt8(ascii: ".")) ? Data([UInt8(ascii: ".")]) + line : line
        }
        var result = Data()
        for line in lines {
            result.append(line)
            result.append(crlf)
        }
        result.append(Data(".\r\n".utf8))
        return result
    }

    /// 按行拆分（不带行尾 CRLF），容忍最后无 CRLF
    static func splitLines(_ data: Data) -> [Data] {
        var lines: [Data] = []
        var current = Data()
        var i = 0
        let bytes = [UInt8](data)
        while i < bytes.count {
            if bytes[i] == UInt8(ascii: "\r"), i + 1 < bytes.count, bytes[i + 1] == UInt8(ascii: "\n") {
                lines.append(current)
                current = Data()
                i += 2
            } else {
                current.append(bytes[i])
                i += 1
            }
        }
        if !current.isEmpty { lines.append(current) }
        return lines
    }

    // MARK: - 底层

    /// EHLO 可能多行（250-xxx 续行直到 "250 " 结束），必须读尽否则后续命令错位
    private func ehlo() async throws {
        try await conn.sendLine("EHLO twinperch")
        while true {
            let line = try await conn.readLine()
            if line.hasPrefix("250 ") { return }
            if line.hasPrefix("250-") { continue }
            throw SMTPError.badReply(line)
        }
    }

    private func expect(_ code: String, command: String) async throws -> String {
        try await expectAny([code], command: command)
    }

    private func expectAny(_ codes: [String], command: String) async throws -> String {
        try await conn.sendLine(command)
        let reply = try await conn.readLine()
        guard codes.contains(where: { reply.hasPrefix($0) }) else {
            if reply.hasPrefix("535") || reply.hasPrefix("5") { throw SMTPError.authFailed }
            throw SMTPError.badReply(reply)
        }
        return reply
    }
}
