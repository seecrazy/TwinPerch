import CryptoKit
import Foundation

/// 链棘轮状态（可序列化，由上层加密落盘）。
public struct RatchetState: Codable, Equatable {
    public var root: Data
    public var sendKey: Data           // K_n：下一条待发消息的链密钥
    public var sendIndex: UInt64
    public var sendDhStep: UInt16
    public var recvKey: Data           // K_m：下一个期望接收消息的链密钥
    public var recvIndex: UInt64
    public var recvDhStep: UInt16
    public var skipped: [SkippedKey]
    public var messagesSinceStep: UInt64
    public var lastStepAt: Date
    public var resyncPending: Bool     // 我方已发 syncRequest，等待对方 step-carrier（期间推迟自发 step）
    public var stepRequested: Bool     // 我方收到 syncRequest，允许（响应方）执行 step
    public var stepEKPub: Data?        // 本 dh_step 的临时公钥；随本步每条消息头携带（容忍 carrier 丢失）

    public struct SkippedKey: Codable, Equatable {
        public var step: UInt16
        public var index: UInt64
        public var mk: Data

        public init(step: UInt16, index: UInt64, mk: Data) {
            self.step = step
            self.index = index
            self.mk = mk
        }
    }
}

/// 对称哈希链 + 周期性 DH 重键（TP-Crypt v1 §4）。
///
/// 重键规则（v1 简化，见文档）：发起方可自发 step；响应方仅在收到 syncRequest 后 step；
/// 已发出 syncRequest 但未收到对方 step-carrier 前，双方都推迟新的 step，避免 root 分叉。
/// step-carrier 携带 root 指纹，任何不一致按 sessionDesync 处理（fail-safe：要求重新配对）。
public final class Ratchet {

    public let isInitiator: Bool
    let myIK: Curve25519.KeyAgreement.PrivateKey
    let peerIKPub: Curve25519.KeyAgreement.PublicKey
    let kConfirm: Data
    public private(set) var state: RatchetState

    /// 从握手产物初始化新会话。
    public convenience init(material: HandshakeMaterial,
                            myIK: Curve25519.KeyAgreement.PrivateKey,
                            peerIKPub: Curve25519.KeyAgreement.PublicKey) {
        let state = RatchetState(
            root: material.root,
            sendKey: material.mySendSeed,
            sendIndex: 0, sendDhStep: 0,
            recvKey: material.peerSendSeed,
            recvIndex: 0, recvDhStep: 0,
            skipped: [], messagesSinceStep: 0,
            lastStepAt: Date(), resyncPending: false, stepRequested: false,
            stepEKPub: nil
        )
        self.init(isInitiator: material.isInitiator, myIK: myIK, peerIKPub: peerIKPub,
                  kConfirm: material.kConfirm, state: state)
    }

    /// 从持久化状态恢复。
    public init(isInitiator: Bool,
                myIK: Curve25519.KeyAgreement.PrivateKey,
                peerIKPub: Curve25519.KeyAgreement.PublicKey,
                kConfirm: Data,
                state: RatchetState) {
        self.isInitiator = isInitiator
        self.myIK = myIK
        self.peerIKPub = peerIKPub
        self.kConfirm = kConfirm
        self.state = state
    }

    // MARK: - 发送

    /// 取下一条消息的密钥并推进链状态。`ekPub` 非 nil 表示本条消息是 step-carrier。
    public func nextMessageKeys() throws -> (mk: Data, dhStep: UInt16, index: UInt64, ekPub: Data?, rootFP: Data) {
        if shouldStep() {
            try performStep()
        }
        let k1 = TP.hmac(state.sendKey, Data([0x01]))
        let mk = TP.hmac(k1, TP.concat(Data([0x02]), TP.le64(state.sendIndex)))
        let idx = state.sendIndex
        state.sendKey = k1
        state.sendIndex &+= 1
        state.messagesSinceStep &+= 1

        let ekPub = state.stepEKPub
        let rootFP = Data(TP.hmac(kConfirm, state.root).prefix(4))
        return (mk, state.sendDhStep, idx, ekPub, rootFP)
    }

    private func shouldStep() -> Bool {
        guard !state.resyncPending else { return false }
        guard isInitiator || state.stepRequested else { return false }
        let byCount = state.messagesSinceStep >= TP.ratchetStepMessages
        let byTime = Date().timeIntervalSince(state.lastStepAt) > 7 * 24 * 3600
        return byCount || byTime || state.stepRequested
    }

    /// DH 重键。发起方可在边界自发调用；响应方仅在 stepRequested 时经 shouldStep 进入。
    func performStep() throws {
        let ek = TP.generateX25519()
        let dhOut = TP.dhRaw(ek, peerIKPub)
        let newRoot = TP.hkdf(dhOut, salt: state.root, info: TP.infoStep)
        let seed = TP.hkdf(newRoot, info: isInitiator ? TP.infoChainA : TP.infoChainB)
        state.root = newRoot
        state.sendKey = seed
        state.sendIndex = 0
        state.sendDhStep &+= 1
        state.messagesSinceStep = 0
        state.lastStepAt = Date()
        state.stepRequested = false
        state.stepEKPub = TP.pubOf(ek)
    }

    /// 发起方收到对端的 syncRequest 后调用：下次发送强制 step。
    public func requestStep() {
        state.stepRequested = true
    }

    /// 我方发出 syncRequest 后调用：在收到对方 step-carrier 前推迟我方自发 step，避免 root 分叉。
    public func markResyncRequested() {
        state.resyncPending = true
    }

    // MARK: - 接收

    /// 对 envelope 头部与链状态求出 message_key。解密失败时由调用方处理。
    public func messageKey(for env: Envelope) throws -> Data {
        if env.dhStep > state.recvDhStep {
            // step-carrier：对方执行了 DH 重键
            guard env.ekPub != Data(repeating: 0, count: 32) else { throw TPError.invalidInput }
            let peerEK = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: env.ekPub)
            let dhOut = TP.dhRaw(myIK, peerEK)
            let newRoot = TP.hkdf(dhOut, salt: state.root, info: TP.infoStep)
            guard env.rootFP == Data(TP.hmac(kConfirm, newRoot).prefix(4)) else {
                throw TPError.sessionDesync
            }
            // 步进方是对端，新链 = 对方的发送链：对端为发起方时是 chain-a，否则 chain-b
            let stepperChainInfo = isInitiator ? TP.infoChainB : TP.infoChainA
            state.root = newRoot
            state.recvKey = TP.hkdf(newRoot, info: stepperChainInfo)
            state.recvIndex = 0
            state.recvDhStep = env.dhStep
            state.resyncPending = false
        } else if env.dhStep == state.recvDhStep {
            guard env.rootFP == Data(TP.hmac(kConfirm, state.root).prefix(4)) else {
                throw TPError.sessionDesync
            }
        }
        if env.dhStep < state.recvDhStep {
            // 旧链消息：只能来自跳过表，绝不推进当前链（否则会把旧序号误当未来消息）
            guard let hit = state.skipped.first(where: { $0.step == env.dhStep && $0.index == env.chainIndex }) else {
                throw TPError.unknownChainIndex
            }
            return hit.mk
        }
        return try deriveMessageKey(env)
    }

    /// 解密成功后移除对应跳过键。
    public func consumeSkipped(step: UInt16, index: UInt64) {
        state.skipped.removeAll { $0.step == step && $0.index == index }
    }

    private func deriveMessageKey(_ env: Envelope) throws -> Data {
        if env.chainIndex >= state.recvIndex {
            let gap = Int(env.chainIndex - state.recvIndex)
            guard state.skipped.count + gap <= TP.skippedKeyCap else {
                throw TPError.skippedStoreOverflow
            }
            var key = state.recvKey
            for i in state.recvIndex..<env.chainIndex {
                let k1 = TP.hmac(key, Data([0x01]))
                let mkI = TP.hmac(k1, TP.concat(Data([0x02]), TP.le64(i)))
                state.skipped.append(.init(step: env.dhStep, index: i, mk: mkI))
                key = k1
            }
            let k1 = TP.hmac(key, Data([0x01]))
            let mkTarget = TP.hmac(k1, TP.concat(Data([0x02]), TP.le64(env.chainIndex)))
            state.recvKey = k1
            state.recvIndex = env.chainIndex + 1
            return mkTarget
        } else {
            guard let hit = state.skipped.first(where: { $0.step == env.dhStep && $0.index == env.chainIndex }) else {
                throw TPError.unknownChainIndex
            }
            return hit.mk
        }
    }

    /// 我方已处理完的对方链最大 index（用于捎带 ACK）。
    public var ackIndex: UInt64? {
        state.recvIndex > 0 ? state.recvIndex - 1 : nil
    }
}
