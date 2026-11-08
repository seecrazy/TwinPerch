import CryptoKit
import XCTest
@testable import TwinPerchKit

final class VaultTests: XCTestCase {

    private var tmpDir: URL!

    override func setUp() {
        super.setUp()
        tmpDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("twinperch-vault-test-\(UUID().uuidString)")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tmpDir)
        super.tearDown()
    }

    private func makeVault() throws -> Vault {
        try Vault(at: tmpDir.appendingPathComponent("vault.db"), keyStore: InMemoryKeyStore())
    }

    func testMessageRoundTrip() throws {
        let vault = try makeVault()
        _ = try vault.appendMessage(timestamp: 1_700_000_000_000, isOutgoing: true,
                                    kind: Int32(Envelope.Kind.text.rawValue),
                                    body: Data("你好，双栖".utf8), meta: Data("{}".utf8))
        _ = try vault.appendMessage(timestamp: 1_700_000_000_001, isOutgoing: false,
                                    kind: Int32(Envelope.Kind.text.rawValue),
                                    body: Data("收到！".utf8), meta: Data("{}".utf8))
        XCTAssertEqual(try vault.messageCount(), 2)
        let rows = try vault.messages()
        XCTAssertEqual(rows[0].isOutgoing, true)
        XCTAssertEqual(String(data: rows[0].body, encoding: .utf8), "你好，双栖")
        XCTAssertEqual(rows[1].isOutgoing, false)
        XCTAssertEqual(String(data: rows[1].body, encoding: .utf8), "收到！")
    }

    func testAtRestDataIsCiphertext() throws {
        let secret = "TOPSECRET-PLAINTEXT"
        let vault = try makeVault()
        _ = try vault.appendMessage(timestamp: 1, isOutgoing: true, kind: 0,
                                    body: Data(secret.utf8), meta: Data())
        // 直接扫库文件：明文不得出现
        let raw = try Data(contentsOf: tmpDir.appendingPathComponent("vault.db"))
        XCTAssertNil(String(data: raw, encoding: .utf8)?.range(of: secret), "明文出现在库文件里！")
        // WAL 也不许有
        let wal = try? Data(contentsOf: tmpDir.appendingPathComponent("vault.db-wal"))
        if let wal {
            XCTAssertNil(String(data: wal, encoding: .utf8)?.range(of: secret), "明文出现在 WAL 里！")
        }
    }

    func testKVOverwrite() throws {
        let vault = try makeVault()
        try vault.setKV("session", data: Data("v1".utf8))
        try vault.setKV("session", data: Data("v2".utf8))
        XCTAssertEqual(try vault.value(forKey: "session"), Data("v2".utf8))
        XCTAssertNil(try vault.value(forKey: "missing"))
    }

    func testReopenRetainsDataWithPersistedKey() throws {
        let keyStore = InMemoryKeyStore()
        let url = tmpDir.appendingPathComponent("vault.db")
        let v1 = try Vault(at: url, keyStore: keyStore)
        _ = try v1.appendMessage(timestamp: 7, isOutgoing: false, kind: 0,
                                 body: Data("persist".utf8), meta: Data())
        try v1.setKV("state", data: Data("S1".utf8))

        let v2 = try Vault(at: url, keyStore: keyStore)
        let rows = try v2.messages()
        XCTAssertEqual(String(data: rows[0].body, encoding: .utf8), "persist")
        XCTAssertEqual(try v2.value(forKey: "state"), Data("S1".utf8))
    }

    func testWrongVaultKeyCannotDecrypt() throws {
        let url = tmpDir.appendingPathComponent("vault.db")
        let ks1 = InMemoryKeyStore()
        let v1 = try Vault(at: url, keyStore: ks1)
        let blob = try v1.encrypt(Data("private".utf8), table: "messages", recordID: TP.randomBytes(12))

        // 换一把 vault_key 解密同一密文 → 必须失败
        let other = try Vault(at: tmpDir.appendingPathComponent("other.db"), keyStore: InMemoryKeyStore())
        XCTAssertThrowsError(try other.decrypt(blob, table: "messages"))
    }

    func testBackupExclusion() throws {
        _ = try makeVault()
        let values = try tmpDir.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(values.isExcludedFromBackup, true, "目录必须 excludedFromBackup")
    }

    func testSessionStatePersistenceThroughVault() throws {
        // 端到端：会话状态加密落盘 → 恢复 → 继续解密
        let (a, b, _, ikB) = try makePair()
        let m1 = try a.sendText("one")
        _ = try b.receive(m1)
        let m2 = try a.sendText("two")

        let vault = try makeVault()
        try vault.setKV("tp-session", data: try b.exportState())

        let restored = try TwinSession.restore(material: b.material, myIK: ikB,
                                               peerIKPub: b.peerIKPub,
                                               stateData: try vault.value(forKey: "tp-session")!)
        let out = try restored.receive(m2)
        guard case .message(.text(_, let body, _)) = out, body == "two" else {
            return XCTFail("restored session decrypt failed: \(out)")
        }
    }
}
