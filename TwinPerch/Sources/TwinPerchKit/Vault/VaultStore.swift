import CryptoKit
import Foundation
import SQLite3

/// Vault 扩展：发件箱（发送失败不丢消息）、附件、分页历史。
/// 与 Vault.swift 同类：列级 AES-GCM，全部表结构在 migrate() 中声明。

extension Vault {

    // MARK: - 发件箱（P0：发送失败不静默丢消息）

    public static let outboxPending: Int32 = 0
    public static let outboxFailed: Int32 = 1

    public struct OutboxRow {
        public var id: Data            // 12 字节 record_nonce 兼主键
        public var createdAt: Int64
        public var state: Int32        // pending / failed
        public var envelope: Data      // 待发送的 Envelope 字节（已加密落库）
        public var preview: String     // 消息预览（重发 UI 用）
        public var attempts: Int32
    }

    @discardableResult
    public func enqueueOutbox(envelope: Data, preview: String, createdAt: Int64) throws -> Data {
        let recordID = TP.randomBytes(12)
        try insert(table: "outbox", recordID: recordID, columns: [
            "created_at": .int(createdAt),
            "state": .int(Int64(Self.outboxPending)),
            "envelope": .blob(try encrypt(envelope, table: "outbox", recordID: recordID)),
            "preview": .blob(try encrypt(Data(preview.utf8), table: "outbox", recordID: recordID)),
            "attempts": .int(0),
        ])
        return recordID
    }

    public func outboxItems() throws -> [OutboxRow] {
        var stmt = try prepare("""
            SELECT id, created_at, state, envelope, preview, attempts
            FROM outbox ORDER BY created_at ASC
            """)
        defer { sqlite3_finalize(stmt) }
        var rows = [OutboxRow]()
        while sqlite3_step(stmt) == SQLITE_ROW {
            let idLen = Int(sqlite3_column_bytes(stmt, 0))
            let id = Data(bytes: sqlite3_column_blob(stmt, 0), count: idLen)
            let created = sqlite3_column_int64(stmt, 1)
            let state = sqlite3_column_int(stmt, 2)
            let envBlobLen = Int(sqlite3_column_bytes(stmt, 3))
            let envBlob = Data(bytes: sqlite3_column_blob(stmt, 3), count: envBlobLen)
            let prevBlobLen = Int(sqlite3_column_bytes(stmt, 4))
            let prevBlob = Data(bytes: sqlite3_column_blob(stmt, 4), count: prevBlobLen)
            let attempts = sqlite3_column_int(stmt, 5)
            rows.append(OutboxRow(
                id: id, createdAt: created, state: state,
                envelope: try decrypt(envBlob, table: "outbox"),
                preview: String(decoding: try decrypt(prevBlob, table: "outbox"), as: UTF8.self),
                attempts: attempts
            ))
        }
        return rows
    }

    public func markOutbox(id: Data, state: Int32, incrementAttempts: Bool = false) throws {
        if incrementAttempts {
            try exec("UPDATE outbox SET state = \(state), attempts = attempts + 1 WHERE id = x'\(id.hex())'")
        } else {
            try exec("UPDATE outbox SET state = \(state) WHERE id = x'\(id.hex())'")
        }
    }

    public func removeOutbox(id: Data) throws {
        try exec("DELETE FROM outbox WHERE id = x'\(id.hex())'")
    }

    // MARK: - 附件（图片/文件；加密落库，≤ 单块上限由调用方分块）

    public struct AttachmentMeta: Codable {
        public var name: String
        public var mime: String
        public var size: Int
        public var isImage: Bool

        public init(name: String, mime: String, size: Int, isImage: Bool) {
            self.name = name
            self.mime = mime
            self.size = size
            self.isImage = isImage
        }
    }

    /// 保存附件（内容加密）。返回 fileID（12 字节 hex；兼作记录 nonce）。
    @discardableResult
    public func saveAttachment(name: String, mime: String, data: Data, timestamp: Int64) throws -> Data {
        let recordID = TP.randomBytes(12)
        let meta = AttachmentMeta(name: name, mime: mime, size: data.count, isImage: mime.hasPrefix("image/"))
        try insert(table: "attachments", recordID: recordID, columns: [
            "ts": .int(timestamp),
            "body": .blob(try encrypt(data, table: "attachments", recordID: recordID)),
            "meta": .blob(try encrypt(JSONEncoder().encode(meta), table: "attachments", recordID: recordID)),
        ])
        return recordID
    }

    public func attachment(id: Data) throws -> (meta: AttachmentMeta, data: Data) {
        var stmt = try prepare("SELECT body, meta FROM attachments WHERE id = x'\(id.hex())'")
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { throw VaultError.recordNotFound }
        let bodyLen = Int(sqlite3_column_bytes(stmt, 0))
        let bodyBlob = Data(bytes: sqlite3_column_blob(stmt, 0), count: bodyLen)
        let metaLen = Int(sqlite3_column_bytes(stmt, 1))
        let metaBlob = Data(bytes: sqlite3_column_blob(stmt, 1), count: metaLen)
        let meta = try JSONDecoder().decode(AttachmentMeta.self, from: try decrypt(metaBlob, table: "attachments"))
        return (meta, try decrypt(bodyBlob, table: "attachments"))
    }

    // MARK: - 分页历史（修：原 messages() 是"最旧的 500 条"，长历史下应为最新一页）

    /// 最新一页（时间升序返回，便于直接渲染）
    public func latestMessages(limit: Int = 200) throws -> [MessageRow] {
        try queryMessages("SELECT id, ts, dir, kind, body, meta FROM messages ORDER BY ts DESC LIMIT \(Int32(limit))").reversed()
    }

    /// 更早的一页（指定时间戳之前的 limit 条，时间升序返回）
    public func messages(before ts: Int64, limit: Int = 200) throws -> [MessageRow] {
        try queryMessages("SELECT id, ts, dir, kind, body, meta FROM messages WHERE ts < \(ts) ORDER BY ts DESC LIMIT \(Int32(limit))").reversed()
    }

    /// 是否还有更早的历史
    public func hasOlderMessages(than ts: Int64) throws -> Bool {
        var stmt = try prepare("SELECT 1 FROM messages WHERE ts < \(ts) LIMIT 1")
        defer { sqlite3_finalize(stmt) }
        return sqlite3_step(stmt) == SQLITE_ROW
    }
}
