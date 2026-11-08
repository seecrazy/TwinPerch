import CryptoKit
import Foundation
import SQLite3

/// 本地加密库（docs/06 §2）。
/// - SQLite3 系统库，零第三方依赖
/// - 列级 AES-GCM：每条记录 12 字节随机 record_nonce，记录密钥 = HKDF(vault_key, salt=record_nonce, info=表名)
/// - vault_key 存 KeyStore（Keychain）；库文件与所在目录 excludedFromBackup
public enum VaultError: Error, Equatable {
    case openFailed(Int32)
    case sqlFailed(String, Int32)
    case keychainFailure(OSStatus)
    case recordNotFound
    case invalidRecord
}

public final class Vault {
    public static let vaultKeyLabel = "twinperch.vault-key"
    private static let schemaVersion = 1

    private var db: OpaquePointer?
    public let keyStore: KeyStore
    public let url: URL
    private let vaultKey: Data

    /// 打开（或创建）库。vault_key 不存在时自动生成并写入 KeyStore。
    public init(at url: URL, keyStore: KeyStore) throws {
        self.url = url
        self.keyStore = keyStore

        if let existing = try keyStore.load(label: Self.vaultKeyLabel) {
            guard existing.count == 32 else { throw VaultError.invalidRecord }
            vaultKey = existing
        } else {
            let key = TP.randomBytes(32)
            try keyStore.save(label: Self.vaultKeyLabel, data: key)
            vaultKey = key
        }

        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        // 隐私宣称的硬性要求：库不进 iCloud 备份（docs/06 §2）
        var dirURL = dir
        var dirValues = URLResourceValues()
        dirValues.isExcludedFromBackup = true
        try? dirURL.setResourceValues(dirValues)
        if FileManager.default.fileExists(atPath: url.path) {
            var fileURL = url
            var fileValues = URLResourceValues()
            fileValues.isExcludedFromBackup = true
            try? fileURL.setResourceValues(fileValues)
        }

        var handle: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(url.path, &handle, flags, nil) == SQLITE_OK else {
            let code = handle.map { sqlite3_errcode($0) } ?? 0
            throw VaultError.openFailed(code)
        }
        db = handle
        try exec("PRAGMA journal_mode=WAL")
        try migrate()
    }

    deinit {
        if let db { sqlite3_close_v2(db) }
    }

    // MARK: - 消息存取

    public struct MessageRow {
        public var recordID: Data          // 12 字节 record_nonce 兼作主键
        public var timestamp: Int64
        public var isOutgoing: Bool
        public var kind: Int32             // 对应 Envelope.Kind
        public var body: Data              // 解密后的载荷（调用方按 Payload 解释）
        public var meta: Data
    }

    @discardableResult
    public func appendMessage(timestamp: Int64, isOutgoing: Bool, kind: Int32,
                              body: Data, meta: Data) throws -> Data {
        let recordID = TP.randomBytes(12)
        try insert(table: "messages", recordID: recordID, columns: [
            "ts": .int(timestamp),
            "dir": .int(isOutgoing ? 1 : 0),
            "kind": .int(Int64(kind)),
            "body": .blob(try encrypt(body, table: "messages", recordID: recordID)),
            "meta": .blob(try encrypt(meta, table: "messages", recordID: recordID)),
        ])
        return recordID
    }

    public func messages(limit: Int = 500) throws -> [MessageRow] {
        try queryMessages("SELECT id, ts, dir, kind, body, meta FROM messages ORDER BY ts ASC LIMIT \(Int32(limit))")
    }

    public func messageCount() throws -> Int {
        var stmt = try prepare("SELECT COUNT(*) FROM messages")
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { throw VaultError.sqlFailed("count", sqlite3_errcode(db)) }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    // MARK: - KV（会话状态、房间信息等）

    public func setKV(_ key: String, data: Data) throws {
        let recordID = try self.value(forKey: key) != nil
            ? existingRecordID(forKey: key) : TP.randomBytes(12)
        try insert(table: "kv", recordID: recordID, columns: [
            "k": .text(key),
            "v": .blob(try encrypt(data, table: "kv", recordID: recordID)),
        ])
    }

    public func value(forKey key: String) throws -> Data? {
        var stmt = try prepare("SELECT v FROM kv WHERE k = ?")
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        let blobLen = Int(sqlite3_column_bytes(stmt, 0))
        let blob = Data(bytes: sqlite3_column_blob(stmt, 0), count: blobLen)
        return try decrypt(blob, table: "kv")
    }

    // MARK: - 加密

    private func recordKey(table: String, recordID: Data) -> Data {
        TP.hkdf(vaultKey, salt: recordID, info: TP.infoVault + "/" + table, out: 32)
    }

    /// 存储格式：record_nonce(12) ‖ ct ‖ tag(16)
    func encrypt(_ plaintext: Data, table: String, recordID: Data) throws -> Data {
        let key = recordKey(table: table, recordID: recordID)
        let aad = TP.concat(Data(table.utf8), recordID)
        let sealed = try TP.seal(plaintext, encKey: key, nonce: recordID, aad: aad)
        return recordID + sealed
    }

    func decrypt(_ blob: Data, table: String) throws -> Data {
        guard blob.count >= 16 + 12 else { throw VaultError.invalidRecord }
        // record_nonce 在 blob 头部：nonce ‖ ct ‖ tag
        let nonce = blob.prefix(12)
        let ct = Data(blob.dropFirst(12))
        let recordID = Data(nonce)
        let key = recordKey(table: table, recordID: recordID)
        let aad = TP.concat(Data(table.utf8), recordID)
        return try TP.open(ct, encKey: key, nonce: Data(nonce), aad: aad)
    }

    func insert(table: String, recordID: Data, columns: [String: Value]) throws {
        let names = columns.keys.sorted().joined(separator: ",")
        let placeholders = columns.keys.sorted().map { _ in "?" }.joined(separator: ",")
        var stmt = try prepare("INSERT OR REPLACE INTO \(table) (id, \(names)) VALUES (?, \(placeholders))")
        defer { sqlite3_finalize(stmt) }
        bindBlob(stmt, index: 1, data: recordID)
        for (i, name) in columns.keys.sorted().enumerated() {
            switch columns[name]! {
            case .int(let v): sqlite3_bind_int64(stmt, Int32(i + 2), v)
            case .text(let v): sqlite3_bind_text(stmt, Int32(i + 2), v, -1, SQLITE_TRANSIENT)
            case .blob(let v): bindBlob(stmt, index: Int32(i + 2), data: v)
            }
        }
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw VaultError.sqlFailed("insert \(table)", sqlite3_errcode(db))
        }
    }

    private func existingRecordID(forKey key: String) throws -> Data {
        var stmt = try prepare("SELECT id FROM kv WHERE k = ?")
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { throw VaultError.recordNotFound }
        let len = Int(sqlite3_column_bytes(stmt, 0))
        return Data(bytes: sqlite3_column_blob(stmt, 0), count: len)
    }

    func queryMessages(_ sql: String) throws -> [MessageRow] {
        var stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        var rows = [MessageRow]()
        while sqlite3_step(stmt) == SQLITE_ROW {
            let idLen = Int(sqlite3_column_bytes(stmt, 0))
            let id = Data(bytes: sqlite3_column_blob(stmt, 0), count: idLen)
            let ts = sqlite3_column_int64(stmt, 1)
            let dir = sqlite3_column_int(stmt, 2)
            let kind = sqlite3_column_int(stmt, 3)
            let bodyBlobLen = Int(sqlite3_column_bytes(stmt, 4))
            let bodyBlob = Data(bytes: sqlite3_column_blob(stmt, 4), count: bodyBlobLen)
            let metaBlobLen = Int(sqlite3_column_bytes(stmt, 5))
            let metaBlob = Data(bytes: sqlite3_column_blob(stmt, 5), count: metaBlobLen)
            rows.append(MessageRow(
                recordID: id, timestamp: ts, isOutgoing: dir == 1, kind: kind,
                body: try decrypt(bodyBlob, table: "messages"),
                meta: try decrypt(metaBlob, table: "messages")
            ))
        }
        return rows
    }

    // MARK: - SQLite 基础设施

    enum Value {
        case int(Int64)
        case text(String)
        case blob(Data)
    }

    private func migrate() throws {
        try exec("""
        CREATE TABLE IF NOT EXISTS messages (
          id BLOB PRIMARY KEY, ts INTEGER NOT NULL, dir INTEGER NOT NULL,
          kind INTEGER NOT NULL, body BLOB NOT NULL, meta BLOB NOT NULL);
        """)
        try exec("CREATE TABLE IF NOT EXISTS kv (id BLOB PRIMARY KEY, k TEXT UNIQUE NOT NULL, v BLOB NOT NULL)")
        try exec("CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts)")
        try exec("CREATE TABLE IF NOT EXISTS outbox (id BLOB PRIMARY KEY, created_at INTEGER NOT NULL, state INTEGER NOT NULL, envelope BLOB NOT NULL, preview BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)")
        try exec("CREATE TABLE IF NOT EXISTS attachments (id BLOB PRIMARY KEY, ts INTEGER NOT NULL, body BLOB NOT NULL, meta BLOB NOT NULL)")
        try setKV("schema_version", data: Data([UInt8(Self.schemaVersion)]))
    }

    func exec(_ sql: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        guard sqlite3_exec(db, sql, nil, nil, &err) == SQLITE_OK else {
            let msg = err.map { String(cString: $0) } ?? "unknown"
            if let err { sqlite3_free(err) }
            throw VaultError.sqlFailed(msg, sqlite3_errcode(db))
        }
    }

    func prepare(_ sql: String) throws -> OpaquePointer {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw VaultError.sqlFailed(sql, sqlite3_errcode(db))
        }
        return stmt!
    }

    private func bindBlob(_ stmt: OpaquePointer, index: Int32, data: Data) {
        _ = data.withUnsafeBytes { bytes in
            sqlite3_bind_blob(stmt, index, bytes.baseAddress, Int32(data.count), SQLITE_TRANSIENT)
        }
    }
}

private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
