import Foundation

/// TP-Crypt v1 消息封装（传输无关的二进制格式）。
///
/// 布局（与 docs/01-加密协议.md §5 对应）：
/// ```
///  0  version     u8
///  1  type        u8
///  2  dh_step     u16 LE
///  4  chain_index u64 LE
/// 12  session_id  16
/// 28  ek_pub      32（dh_step 变化后的首条消息携带，否则全 0）
/// 60  root_fp     4（HMAC(k_confirm, root)[0..<4]，连续性校验）
/// 64  nonce       12
/// 76  ct_len      u32 LE
/// 80  ciphertext  ct_len 字节（ChaCha20-Poly1305 combined，含 16 字节 tag）
/// ```
/// AAD = version ‖ type ‖ dh_step ‖ chain_index ‖ session_id ‖ ek_pub ‖ root_fp ‖ nonce
public struct Envelope: Equatable {
    public enum Kind: UInt8 {
        case text = 0
        case manifest = 1
        case ack = 3
        case read = 4
        case syncRequest = 5
        case keyNotice = 6
    }

    public var version: UInt8
    public var kind: Kind
    public var dhStep: UInt16
    public var chainIndex: UInt64
    public var sessionID: Data      // 16
    public var ekPub: Data          // 32
    public var rootFP: Data         // 4
    public var nonce: Data          // 12
    public var ciphertext: Data

    public init(kind: Kind, dhStep: UInt16, chainIndex: UInt64, sessionID: Data,
                ekPub: Data, rootFP: Data, nonce: Data, ciphertext: Data) {
        self.version = TP.version
        self.kind = kind
        self.dhStep = dhStep
        self.chainIndex = chainIndex
        self.sessionID = sessionID
        self.ekPub = ekPub
        self.rootFP = rootFP
        self.nonce = nonce
        self.ciphertext = ciphertext
    }

    public var headerSize: Int { 80 }

    public func encode() throws -> Data {
        guard sessionID.count == 16, ekPub.count == 32, rootFP.count == 4, nonce.count == 12 else {
            throw TPError.invalidInput
        }
        var out = Data()
        out.append(version)
        out.append(kind.rawValue)
        out.append(TP.le16(dhStep))
        out.append(TP.le64(chainIndex))
        out.append(sessionID)
        out.append(ekPub)
        out.append(rootFP)
        out.append(nonce)
        out.append(TP.le32(UInt32(ciphertext.count)))
        out.append(ciphertext)
        return out
    }

    public static func decode(_ data: Data) throws -> Envelope {
        guard data.count >= 80 else { throw TPError.invalidInput }
        guard data[0] == TP.version else { throw TPError.invalidInput }
        guard let kind = Kind(rawValue: data[1]) else { throw TPError.invalidInput }
        let ctLen = Int(TP.readLE32(data, 76))
        guard data.count == 80 + ctLen else { throw TPError.invalidInput }
        return Envelope(
            kind: kind,
            dhStep: TP.readLE16(data, 2),
            chainIndex: TP.readLE64(data, 4),
            sessionID: TP.slice(data, 12..<28),
            ekPub: TP.slice(data, 28..<60),
            rootFP: TP.slice(data, 60..<64),
            nonce: TP.slice(data, 64..<76),
            ciphertext: TP.slice(data, 80..<(80 + ctLen))
        )
    }

    public var aad: Data {
        TP.concat(
            Data([version, kind.rawValue]),
            TP.le16(dhStep), TP.le64(chainIndex),
            sessionID, ekPub, rootFP, nonce
        )
    }

    // MARK: - 载荷（密文内层，CBOR）

    public struct Payload {
        public var kind: Kind
        public var body: String?
        public var messageID: String?
        public var timestamp: UInt64?     // 毫秒
        public var ackIndex: UInt64?      // 我方已处理完的对方链最大 index
        public var readIndex: UInt64?     // 我方已读的对方链最大 index

        public init(kind: Kind, body: String? = nil, messageID: String? = nil,
                    timestamp: UInt64? = nil, ackIndex: UInt64? = nil, readIndex: UInt64? = nil) {
            self.kind = kind
            self.body = body
            self.messageID = messageID
            self.timestamp = timestamp
            self.ackIndex = ackIndex
            self.readIndex = readIndex
        }

        public func encode() -> Data {
            var dict: [String: CBOR.Value] = ["t": .uint(UInt64(kind.rawValue))]
            if let b = body { dict["b"] = .text(b) }
            if let m = messageID { dict["m"] = .text(m) }
            if let ts = timestamp { dict["ts"] = .uint(ts) }
            if let a = ackIndex { dict["ack"] = .uint(a) }
            if let r = readIndex { dict["read"] = .uint(r) }
            return CBOR.encodeMap(dict)
        }

        public static func decode(_ data: Data) throws -> Payload {
            let map = try CBOR.decodeMap(data)
            guard case .uint(let t)? = map["t"], let kind = Kind(rawValue: UInt8(t)) else {
                throw TPError.invalidInput
            }
            func text(_ k: String) -> String? {
                if case .text(let s)? = map[k] { return s }
                return nil
            }
            func uint(_ k: String) -> UInt64? {
                if case .uint(let u)? = map[k] { return u }
                return nil
            }
            return Payload(
                kind: kind,
                body: text("b"), messageID: text("m"),
                timestamp: uint("ts"), ackIndex: uint("ack"), readIndex: uint("read")
            )
        }
    }
}
