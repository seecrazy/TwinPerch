import CryptoKit
import Foundation

/// 面对面配对二维码载荷。
/// 布局：magic"TPQR"(4) + version(1) + ik_pub(32) + ek_pub(32) + session_id(16) + nonce(16) + addr_len(2 LE) + addr(utf8)
public struct QRPairingPayload {
    public static let magic = Data("TPQR".utf8)

    public let ikPub: Data        // 32
    public let ekPub: Data        // 32
    public let sessionID: Data    // 16
    public let nonce: Data        // 16
    public let address: String?   // 邮箱地址（邮箱传输用），可空

    public init(ikPub: Data, ekPub: Data, sessionID: Data, nonce: Data, address: String? = nil) {
        self.ikPub = ikPub
        self.ekPub = ekPub
        self.sessionID = sessionID
        self.nonce = nonce
        self.address = address
    }

    public func encode() throws -> Data {
        guard ikPub.count == 32, ekPub.count == 32, sessionID.count == 16, nonce.count == 16 else {
            throw TPError.invalidInput
        }
        let addrData = address.map { Data($0.utf8) } ?? Data()
        guard addrData.count <= UInt16.max else { throw TPError.invalidInput }
        var out = Data()
        out.append(Self.magic)
        out.append(TP.version)
        out.append(ikPub)
        out.append(ekPub)
        out.append(sessionID)
        out.append(nonce)
        out.append(TP.le16(UInt16(addrData.count)))
        out.append(addrData)
        return out
    }

    public static func decode(_ data: Data) throws -> QRPairingPayload {
        guard data.starts(with: magic), data.count >= 103, data[4] == TP.version else {
            throw TPError.invalidInput
        }
        let addrLen = TP.readLE16(data, 101)
        let expected = 103 + Int(addrLen)
        guard data.count == expected else { throw TPError.invalidInput }
        let addr = addrLen > 0 ? String(data: data.subdata(in: 103..<expected), encoding: .utf8) : nil
        return QRPairingPayload(
            ikPub: TP.slice(data, 5..<37),
            ekPub: TP.slice(data, 37..<69),
            sessionID: TP.slice(data, 69..<85),
            nonce: TP.slice(data, 85..<101),
            address: addr
        )
    }
}

/// 握手产物：会话全部长期派生物。
public struct HandshakeMaterial {
    public let sessionID: Data
    public let master: Data
    public let root: Data
    public let mySendSeed: Data       // 我方发送链种子（initiator → chain-a）
    public let peerSendSeed: Data     // 对方发送链种子（我方接收链）
    public let kRoom: Data
    public let roomID: Data
    public let kConfirm: Data
    public let safetyCodeHex: String  // 16 hex 字符，8 组×4，双方一致
    public let isInitiator: Bool
    public let peerAddress: String?
}

public enum Handshake {

    /// 发起方（A）第 1 步：生成自己的临时参数并产出二维码内容。
    /// - Parameters:
    ///   - ik: A 的身份私钥
    ///   - address: A 在邮箱传输中使用的地址
    public static func initiatorStart(ik: Curve25519.KeyAgreement.PrivateKey,
                                      address: String?) throws -> (ek: Curve25519.KeyAgreement.PrivateKey,
                                                                   sessionID: Data, nonce: Data, qr: Data) {
        let ek = TP.generateX25519()
        let sid = TP.randomBytes(16)
        let nonce = TP.randomBytes(16)
        let payload = QRPairingPayload(
            ikPub: TP.pubOf(ik), ekPub: TP.pubOf(ek),
            sessionID: sid, nonce: nonce, address: address
        )
        return (ek, sid, nonce, try payload.encode())
    }

    /// 发起方（A）第 3 步：扫描 B 的二维码后完成握手。
    public static func initiatorComplete(ik: Curve25519.KeyAgreement.PrivateKey,
                                         ek: Curve25519.KeyAgreement.PrivateKey,
                                         sessionID: Data, myNonce: Data,
                                         peerQR: Data) throws -> HandshakeMaterial {
        let peer = try QRPairingPayload.decode(peerQR)
        guard peer.sessionID == sessionID else { throw TPError.invalidInput }
        let peerIK = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer.ikPub)
        let peerEK = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer.ekPub)
        return try complete(
            isInitiator: true, sessionID: sessionID,
            myIK: ik, myEK: ek, myNonce: myNonce,
            peerIK: peerIK, peerEK: peerEK, peerNonce: peer.nonce, peerAddress: peer.address
        )
    }

    /// 响应方（B）：扫描 A 的二维码，生成自己的临时参数，产出回扫二维码并完成握手。
    public static func responderComplete(myIK: Curve25519.KeyAgreement.PrivateKey,
                                         scannedQR: Data,
                                         address: String?) throws -> (ek: Curve25519.KeyAgreement.PrivateKey,
                                                                      myNonce: Data, myQR: Data,
                                                                      material: HandshakeMaterial) {
        let peer = try QRPairingPayload.decode(scannedQR)
        let peerIK = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer.ikPub)
        let peerEK = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer.ekPub)
        let ek = TP.generateX25519()
        let myNonce = TP.randomBytes(16)
        let mine = QRPairingPayload(
            ikPub: TP.pubOf(myIK), ekPub: TP.pubOf(ek),
            sessionID: peer.sessionID, nonce: myNonce, address: address
        )
        let material = try complete(
            isInitiator: false, sessionID: peer.sessionID,
            myIK: myIK, myEK: ek, myNonce: myNonce,
            peerIK: peerIK, peerEK: peerEK, peerNonce: peer.nonce, peerAddress: peer.address
        )
        return (ek, myNonce, try mine.encode(), material)
    }

    // MARK: - 私有：双方对称的推导

    private static func complete(isInitiator: Bool, sessionID: Data,
                                 myIK: Curve25519.KeyAgreement.PrivateKey,
                                 myEK: Curve25519.KeyAgreement.PrivateKey,
                                 myNonce: Data,
                                 peerIK: Curve25519.KeyAgreement.PublicKey,
                                 peerEK: Curve25519.KeyAgreement.PublicKey,
                                 peerNonce: Data, peerAddress: String?) throws -> HandshakeMaterial {
        // DH1/DH4 天然对称；DH2/DH3 按"发起方/响应方"角色统一（双方计算相同集合）：
        //   DH2 = X25519(发起方IK, 响应方EK)   DH3 = X25519(发起方EK, 响应方IK)
        // 响应方侧即 DH2 = (我的EK, 对方IK)、DH3 = (我的IK, 对方EK)。
        let d1 = TP.dhRaw(myIK, peerIK)
        let d2 = isInitiator ? TP.dhRaw(myIK, peerEK) : TP.dhRaw(myEK, peerIK)
        let d3 = isInitiator ? TP.dhRaw(myEK, peerIK) : TP.dhRaw(myIK, peerEK)
        let d4 = TP.dhRaw(myEK, peerEK)
        let salt = isInitiator ? TP.concat(myNonce, peerNonce) : TP.concat(peerNonce, myNonce)
        let master = TP.hkdf(TP.concat(d1, d2, d3, d4), salt: salt, info: TP.infoMaster)

        let root = TP.hkdf(master, info: TP.infoRoot)
        let mySend = TP.hkdf(master, info: isInitiator ? TP.infoChainA : TP.infoChainB)
        let peerSend = TP.hkdf(master, info: isInitiator ? TP.infoChainB : TP.infoChainA)
        let kRoom = TP.hkdf(master, info: TP.infoRoomAuth)
        let roomID = TP.hkdf(master, info: TP.infoRoomID, out: 16)
        let kConfirm = TP.hkdf(master, info: TP.infoConfirm)

        // 安全码：SHA256(initiator_pub ‖ responder_pub) 前 8 字节
        let initPub = isInitiator ? TP.pubOf(myIK) : peerIK.rawRepresentation
        let respPub = isInitiator ? peerIK.rawRepresentation : TP.pubOf(myIK)
        let safety = TP.sha256(TP.concat(initPub, respPub)).prefix(8).hex()

        return HandshakeMaterial(
            sessionID: sessionID, master: master, root: root,
            mySendSeed: mySend, peerSendSeed: peerSend,
            kRoom: kRoom, roomID: roomID, kConfirm: kConfirm,
            safetyCodeHex: safety, isInitiator: isInitiator,
            peerAddress: peerAddress
        )
    }
}
