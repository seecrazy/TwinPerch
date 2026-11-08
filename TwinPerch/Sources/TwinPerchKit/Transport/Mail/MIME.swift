import Foundation

/// TwinPerch 邮件的 MIME 构造与解析（docs/03 §2）。
/// 格式由本 App 严格掌控（定长 Subject、单一 attachment 段），解析器只处理自有格式，
/// 保持实现最小。主题恒为 "TwinPerch"，不含任何内容信息。

public enum MIMEError: Error, Equatable {
    case malformed
    case attachmentNotFound
    case badBase64
}

public struct TwinMessage {
    public let from: String
    public let to: String
    /// 传输层消息 ID（UUID），Message-ID 头 = <uuid@twinperch>
    public let transportID: String
    /// Envelope 密文（附件载荷）
    public let payload: Data

    public init(from: String, to: String, transportID: String, payload: Data) {
        self.from = from
        self.to = to
        self.transportID = transportID
        self.payload = payload
    }
}

public enum MIME {

    static let boundary = "=TP-BOUNDARY="
    static let subject = "TwinPerch"
    static let attachmentName = "twinperch.dat"

    // MARK: - 构造

    public static func encode(_ message: TwinMessage, date: Date = Date()) -> Data {
        let b64 = base64Lines(message.payload)
        let text =
            "From: \(message.from)\r\n" +
            "To: \(message.to)\r\n" +
            "Subject: \(subject)\r\n" +
            "Message-ID: <\(message.transportID)@twinperch>\r\n" +
            "Date: \(rfc5322Date(date))\r\n" +
            "MIME-Version: 1.0\r\n" +
            "Content-Type: multipart/mixed; boundary=\"\(boundary)\"\r\n" +
            "\r\n" +
            "This is a TwinPerch encrypted message.\r\n" +
            "--\(boundary)\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Content-Transfer-Encoding: 7bit\r\n" +
            "\r\n" +
            "\r\n" +
            "--\(boundary)\r\n" +
            "Content-Type: application/octet-stream; name=\"\(attachmentName)\"\r\n" +
            "Content-Transfer-Encoding: base64\r\n" +
            "Content-Disposition: attachment; filename=\"\(attachmentName)\"\r\n" +
            "\r\n" +
            b64 +
            "--\(boundary)--\r\n"
        return Data(text.utf8)
    }

    /// RFC 5322 日期（GMT）
    static func rfc5322Date(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "GMT")
        f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
        return f.string(from: date)
    }

    static func base64Lines(_ data: Data) -> String {
        let encoded = data.base64EncodedString()
        var lines: [String] = []
        var idx = encoded.startIndex
        while idx < encoded.endIndex {
            let end = encoded.index(idx, offsetBy: 76, limitedBy: encoded.endIndex) ?? encoded.endIndex
            lines.append(String(encoded[idx..<end]))
            idx = end
        }
        return lines.joined(separator: "\r\n") + "\r\n"
    }

    // MARK: - 解析

    public static func decode(_ data: Data) throws -> TwinMessage {
        guard let text = String(data: data, encoding: .utf8) else { throw MIMEError.malformed }
        let (headers, body) = try splitHeadersBody(text)

        let from = header(headers, "From") ?? ""
        let to = header(headers, "To") ?? ""
        let messageID = header(headers, "Message-ID") ?? ""
        let transportID = transportID(fromMessageID: messageID)

        guard body.contains(boundary) else { throw MIMEError.malformed }
        guard let payload = extractAttachment(body) else { throw MIMEError.attachmentNotFound }

        return TwinMessage(from: from, to: to, transportID: transportID, payload: payload)
    }

    static func transportID(fromMessageID messageID: String) -> String {
        // <uuid@twinperch> → uuid
        var s = messageID.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("<") { s.removeFirst() }
        if s.hasSuffix(">") { s.removeLast() }
        if let at = s.range(of: "@twinperch") {
            s = String(s[..<at.lowerBound])
        }
        return s
    }

    static func splitHeadersBody(_ text: String) throws -> (headers: String, body: String) {
        guard let range = text.range(of: "\r\n\r\n") else { throw MIMEError.malformed }
        return (String(text[..<range.lowerBound]), String(text[range.upperBound...]))
    }

    static func header(_ headers: String, _ name: String) -> String? {
        for line in headers.components(separatedBy: "\r\n") {
            if line.lowercased().hasPrefix(name.lowercased() + ":") {
                return String(line.dropFirst(name.count + 1)).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    /// 取 attachment 段的 base64 载荷并解码（容忍换行/空白）
    static func extractAttachment(_ body: String) -> Data? {
        guard let marker = body.range(of: "Content-Disposition: attachment") else { return nil }
        let section = String(body[marker.upperBound...])
        guard let blank = section.range(of: "\r\n\r\n") else { return nil }
        var b64Part = String(section[blank.upperBound...])
        // 截到收尾边界
        if let endMarker = b64Part.range(of: "--\(boundary)") {
            b64Part = String(b64Part[..<endMarker.lowerBound])
        }
        let cleaned = b64Part
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .trimmingCharacters(in: .whitespaces)
        guard !cleaned.isEmpty, let decoded = Data(base64Encoded: cleaned) else { return nil }
        return decoded
    }
}
