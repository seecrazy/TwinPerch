import CryptoKit
import Foundation

/// 会话层：加密/解密 + 回执捎带 + 去重语义 + 重同步流程。
/// 线上只有 Envelope；一切 ACK/已读都是加密控制帧，传输方不可见。
public final class TwinSession {

    public let material: HandshakeMaterial
    let myIK: Curve25519.KeyAgreement.PrivateKey
    public let peerIKPub: Data
    public let ratchet: Ratchet

    public private(set) var myAckedByPeer: UInt64? = nil   // 对方已收到的我方链最大 index（nil = 尚无回执）
    public private(set) var myReadByPeer: UInt64? = nil    // 对方已读的我方链最大 index
    var localReadUpTo: UInt64? = nil                       // 我方已读的对方链最大 index
    var lastAckSent: UInt64? = nil                         // 我方已发出的 ACK 进度（抑制重复发送）
    var lastReadSent: UInt64? = nil                        // 我方已发出的已读进度

    public init(material: HandshakeMaterial,
                myIK: Curve25519.KeyAgreement.PrivateKey,
                peerIKPub: Data) {
        self.material = material
        self.myIK = myIK
        self.peerIKPub = peerIKPub
        self.ratchet = Ratchet(material: material, myIK: myIK,
                               peerIKPub: try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerIKPub))
    }

    public init(material: HandshakeMaterial,
                myIK: Curve25519.KeyAgreement.PrivateKey,
                peerIKPub: Data,
                ratchetState: RatchetState,
                myAckedByPeer: UInt64?, myReadByPeer: UInt64?, localReadUpTo: UInt64?,
                lastAckSent: UInt64? = nil, lastReadSent: UInt64? = nil) {
        self.material = material
        self.myIK = myIK
        self.peerIKPub = peerIKPub
        self.myAckedByPeer = myAckedByPeer
        self.myReadByPeer = myReadByPeer
        self.localReadUpTo = localReadUpTo
        self.lastAckSent = lastAckSent
        self.lastReadSent = lastReadSent
        self.ratchet = Ratchet(isInitiator: material.isInitiator, myIK: myIK,
                               peerIKPub: try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerIKPub),
                               kConfirm: material.kConfirm, state: ratchetState)
    }

    // MARK: - 持久化（调用方负责加密落盘）

    public struct PersistedState: Codable {
        public var ratchet: RatchetState
        public var myAckedByPeer: UInt64?
        public var myReadByPeer: UInt64?
        public var localReadUpTo: UInt64?
        public var lastAckSent: UInt64?
        public var lastReadSent: UInt64?

        public init(ratchet: RatchetState, myAckedByPeer: UInt64?,
                    myReadByPeer: UInt64?, localReadUpTo: UInt64?,
                    lastAckSent: UInt64? = nil, lastReadSent: UInt64? = nil) {
            self.ratchet = ratchet
            self.myAckedByPeer = myAckedByPeer
            self.myReadByPeer = myReadByPeer
            self.localReadUpTo = localReadUpTo
            self.lastAckSent = lastAckSent
            self.lastReadSent = lastReadSent
        }
    }

    public func exportState() throws -> Data {
        let s = PersistedState(ratchet: ratchet.state, myAckedByPeer: myAckedByPeer,
                               myReadByPeer: myReadByPeer, localReadUpTo: localReadUpTo,
                               lastAckSent: lastAckSent, lastReadSent: lastReadSent)
        return try JSONEncoder().encode(s)
    }

    public static func restore(material: HandshakeMaterial,
                               myIK: Curve25519.KeyAgreement.PrivateKey,
                               peerIKPub: Data,
                               stateData: Data) throws -> TwinSession {
        let s = try JSONDecoder().decode(PersistedState.self, from: stateData)
        return TwinSession(material: material, myIK: myIK, peerIKPub: peerIKPub,
                           ratchetState: s.ratchet, myAckedByPeer: s.myAckedByPeer,
                           myReadByPeer: s.myReadByPeer, localReadUpTo: s.localReadUpTo,
                           lastAckSent: s.lastAckSent, lastReadSent: s.lastReadSent)
    }

    // MARK: - 出站

    /// 发送文本。ACK/已读自动捎带。
    public func sendText(_ body: String, timestamp: UInt64 = nowMillis()) throws -> Envelope {
        let payload = Envelope.Payload(
            kind: .text, body: body,
            messageID: UUID().uuidString, timestamp: timestamp,
            ackIndex: ratchet.ackIndex,
            readIndex: [ratchet.ackIndex, localReadUpTo].compactMap { $0 }.max()
        )
        return try sealEnvelope(kind: .text, payload: payload)
    }

    /// 标记已读（已读进度推进到当前已收到的最大 index）。
    @discardableResult
    public func markRead() -> UInt64? {
        if let a = ratchet.ackIndex { localReadUpTo = max(localReadUpTo ?? a, a) }
        return localReadUpTo
    }

    /// 无普通消息可发时的已读回执帧。
    public func makeReadReceipt() throws -> Envelope? {
        guard let r = localReadUpTo, lastReadSent == nil || r > lastReadSent! else { return nil }
        lastReadSent = r
        if let a = ratchet.ackIndex { lastAckSent = max(lastAckSent ?? a, a) }   // 捎带的 ACK 同样计入已发进度
        let payload = Envelope.Payload(kind: .read, ackIndex: ratchet.ackIndex, readIndex: r)
        return try sealEnvelope(kind: .read, payload: payload)
    }

    /// 无普通消息可发时的纯 ACK 帧。
    public func makeAck() throws -> Envelope? {
        guard let a = ratchet.ackIndex, lastAckSent == nil || a > lastAckSent! else { return nil }
        lastAckSent = a
        let payload = Envelope.Payload(kind: .ack, ackIndex: a)
        return try sealEnvelope(kind: .ack, payload: payload)
    }

    /// 主动重配对（换机/升级密钥）前发送的"安全码已变更"预告。
    /// 对方收到后 UI 显示分隔条；旧 session 保留只读。
    public func makeKeyNotice() throws -> Envelope {
        let payload = Envelope.Payload(kind: .keyNotice, timestamp: Self.nowMillis(),
                                       ackIndex: ratchet.ackIndex)
        return try sealEnvelope(kind: .keyNotice, payload: payload)
    }

    /// 最近一条 manifest 帧解密后的原始 CBOR 字段（附件分块协议由 App 层解释）
    public private(set) var lastPayloadCBOR: [String: CBOR.Value]?

    /// 接收空洞超限后，请求对方重置其发送链。
    public func makeSyncRequest() throws -> Envelope {
        let payload = Envelope.Payload(kind: .syncRequest, ackIndex: ratchet.ackIndex)
        ratchet.markResyncRequested()   // 在收到对方 step-carrier 前推迟我方自发 step
        return try sealEnvelope(kind: .syncRequest, payload: payload)
    }

    /// 自定义 CBOR 载荷的封装（附件分块帧等需要 bytes 字段的场景）
    public func sealRaw(kind: Envelope.Kind, payloadBytes: Data) throws -> Envelope {
        try sealBytes(kind: kind, pt: payloadBytes)
    }

    func sealEnvelope(kind: Envelope.Kind, payload: Envelope.Payload) throws -> Envelope {
        try sealBytes(kind: kind, pt: payload.encode())
    }

    private func sealBytes(kind: Envelope.Kind, pt: Data) throws -> Envelope {
        let keys = try ratchet.nextMessageKeys()
        let encKey = TP.hmac(keys.mk, Data("enc".utf8)).prefix(32)
        let nonce = Data(TP.hmac(keys.mk, Data("nonce".utf8)).prefix(12))
        let env = Envelope(
            kind: kind,
            dhStep: keys.dhStep, chainIndex: keys.index,
            sessionID: material.sessionID,
            ekPub: keys.ekPub ?? Data(repeating: 0, count: 32),
            rootFP: keys.rootFP,
            nonce: nonce,
            ciphertext: Data()
        )
        let ct = try TP.seal(pt, encKey: Data(encKey), nonce: nonce, aad: env.aad)
        var sealed = env
        sealed.ciphertext = ct
        return sealed
    }

    // MARK: - 入站

    public enum Inbound {
        case text(messageID: String, body: String, timestamp: UInt64)
        case receipt(ackIndex: UInt64?, readIndex: UInt64?)
        case keyNotice
    }

    public enum Outcome {
        case message(Inbound)
        case manifest                        // 附件帧：原始字段见 lastPayloadCBOR
        case duplicate                       // 重复投递（at-least-once 语义）
        case resyncRequestedByPeer           // 对方请求我方重置发送链（下次发送时执行 step）
        case needsResync                     // 我方接收空洞超限，应向对方发 syncRequest
    }

    public func receive(_ env: Envelope) throws -> Outcome {
        guard env.sessionID == material.sessionID else { throw TPError.invalidInput }

        if env.kind == .syncRequest {
            ratchet.requestStep()
            return .resyncRequestedByPeer
        }

        let mk: Data
        do {
            mk = try ratchet.messageKey(for: env)
        } catch TPError.unknownChainIndex {
            return .duplicate
        } catch TPError.skippedStoreOverflow {
            return .needsResync
        }

        let pt: Data
        do {
            let encKey = Data(TP.hmac(mk, Data("enc".utf8)).prefix(32))
            pt = try TP.open(env.ciphertext, encKey: encKey, nonce: env.nonce, aad: env.aad)
        } catch {
            throw TPError.decryptFailed
        }
        // 若来自跳过表（迟到消息），成功后移除对应键
        ratchet.consumeSkipped(step: env.dhStep, index: env.chainIndex)

        if env.kind == .manifest, let map = try? CBOR.decodeMap(pt) {
            lastPayloadCBOR = map
        }
        let payload = try Envelope.Payload.decode(pt)
        if let a = payload.ackIndex { myAckedByPeer = max(myAckedByPeer ?? a, a) }
        if let r = payload.readIndex { myReadByPeer = max(myReadByPeer ?? r, r) }

        switch payload.kind {
        case .text:
            guard let b = payload.body else { throw TPError.invalidInput }
            return .message(.text(messageID: payload.messageID ?? "",
                                  body: b, timestamp: payload.timestamp ?? 0))
        case .manifest:
            return .manifest
        case .ack, .read:
            return .message(.receipt(ackIndex: payload.ackIndex, readIndex: payload.readIndex))
        case .keyNotice:
            return .message(.keyNotice)
        case .manifest:
            return .manifest
        case .syncRequest:
            return .resyncRequestedByPeer
        }
    }

    public static func nowMillis() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1000)
    }
}
