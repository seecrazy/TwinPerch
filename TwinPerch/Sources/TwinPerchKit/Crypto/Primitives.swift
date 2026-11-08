import CryptoKit
import Foundation

/// TP-Crypt v1 全局常量与底层原语封装。
/// 仅使用 CryptoKit：X25519 / HKDF-SHA256 / HMAC-SHA256 / ChaCha20-Poly1305 / SHA-256。
public enum TPError: Error, Equatable {
    case invalidInput
    case decryptFailed
    case unknownChainIndex        // index 早于当前状态且不在跳过表
    case skippedStoreOverflow     // 空洞超上限，需重同步
    case sessionDesync            // root 指纹不匹配等不可恢复分歧
    case notStepper               // 非发起方试图主动重键
}

public enum TP {
    public static var version: UInt8 = 1
    public static var skippedKeyCap = 4096
    public static var ratchetStepMessages: UInt64 = 500

    // HKDF info 常量（与 docs/01-加密协议.md 对应）
    static let infoMaster = "TP-crypt-v1"
    static let infoRoot = "root"
    static let infoStep = "root-step"
    static let infoChainA = "chain-a"
    static let infoChainB = "chain-b"
    static let infoRoomAuth = "room-auth"
    static let infoRoomID = "room-id"
    static let infoConfirm = "confirm"
    static let infoVault = "tp-vault-v1"

    // MARK: - 编码工具

    public static func le64(_ v: UInt64) -> Data {
        var o = v.littleEndian
        return withUnsafeBytes(of: &o) { Data($0) }
    }

    public static func le16(_ v: UInt16) -> Data {
        var o = v.littleEndian
        return withUnsafeBytes(of: &o) { Data($0) }
    }

    public static func le32(_ v: UInt32) -> Data {
        var o = v.littleEndian
        return withUnsafeBytes(of: &o) { Data($0) }
    }

    public static func readLE64(_ d: Data, _ offset: Int) -> UInt64 {
        let s = d.subdata(in: offset..<(offset + 8))
        return s.withUnsafeBytes { $0.load(as: UInt64.self).littleEndian }
    }

    public static func readLE16(_ d: Data, _ offset: Int) -> UInt16 {
        let s = d.subdata(in: offset..<(offset + 2))
        return s.withUnsafeBytes { $0.load(as: UInt16.self).littleEndian }
    }

    public static func readLE32(_ d: Data, _ offset: Int) -> UInt32 {
        let s = d.subdata(in: offset..<(offset + 4))
        return s.withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
    }

    public static func concat(_ parts: Data...) -> Data {
        var out = Data()
        for p in parts { out.append(p) }
        return out
    }

    public static func slice(_ d: Data, _ range: Range<Int>) -> Data {
        d.subdata(in: range)
    }

    // MARK: - 原语

    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    public static func hmac(_ key: Data, _ data: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    public static func hkdf(_ ikm: Data, salt: Data? = nil, info: String, out: Int = 32) -> Data {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt ?? Data(),
            info: Data(info.utf8),
            outputByteCount: out
        ).withUnsafeBytes { Data($0) }
    }

    /// X25519 密钥协商，返回 RFC 7748 原始 32 字节输出（已用标准向量验证）。
    public static func dhRaw(_ priv: Curve25519.KeyAgreement.PrivateKey,
                             _ peerPub: Curve25519.KeyAgreement.PublicKey) -> Data {
        let ss = try! priv.sharedSecretFromKeyAgreement(with: peerPub)
        return SymmetricKey(data: ss).withUnsafeBytes { Data($0) }
    }

    /// 随机源可注入（仅测试用）：设置后 randomBytes 从此获取，保证向量可复现。
    public static var randomProvider: ((Int) -> Data)?

    public static func generateX25519() -> Curve25519.KeyAgreement.PrivateKey {
        try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: randomBytes(32))
    }

    public static func x25519(raw: Data) throws -> Curve25519.KeyAgreement.PrivateKey {
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw)
    }

    public static func pubOf(_ priv: Curve25519.KeyAgreement.PrivateKey) -> Data {
        priv.publicKey.rawRepresentation
    }

    // MARK: - AEAD

    /// 返回 ciphertext ‖ tag(16)（不含 nonce；CryptoKit 的 combined 是 nonce‖ct‖tag，须拆开）。
    /// 外层 Data() 重定基：SealedBox 的切片字段 startIndex 非 0，直接拼接会把非零基带出去。
    public static func seal(_ plaintext: Data, encKey: Data, nonce: Data, aad: Data) throws -> Data {
        let sealed = try ChaChaPoly.seal(
            plaintext,
            using: SymmetricKey(data: encKey),
            nonce: ChaChaPoly.Nonce(data: nonce),
            authenticating: aad
        )
        return Data(sealed.ciphertext + sealed.tag)
    }

    public static func `open`(_ ciphertext: Data, encKey: Data, nonce: Data, aad: Data) throws -> Data {
        var combined = nonce
        combined.append(ciphertext)
        let box = try ChaChaPoly.SealedBox(combined: combined)
        return try ChaChaPoly.open(box, using: SymmetricKey(data: encKey), authenticating: aad)
    }

    public static func randomBytes(_ n: Int) -> Data {
        if let provider = randomProvider { return provider(n) }
        var d = Data(count: n)
        _ = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!) }
        return d
    }
}

extension Data {
    public func hex() -> String {
        map { String(format: "%02x", $0) }.joined()
    }

    public static func fromHex(_ s: String) -> Data? {
        var bytes = [UInt8]()
        var t = s
        if t.hasPrefix("0x") { t.removeFirst(2) }
        guard t.count % 2 == 0 else { return nil }
        var idx = t.startIndex
        while idx < t.endIndex {
            let next = t.index(idx, offsetBy: 2)
            guard let b = UInt8(t[idx..<next], radix: 16) else { return nil }
            bytes.append(b)
            idx = next
        }
        return Data(bytes)
    }
}
