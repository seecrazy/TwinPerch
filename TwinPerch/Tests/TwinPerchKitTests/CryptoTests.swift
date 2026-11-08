import CryptoKit
import XCTest
@testable import TwinPerchKit

/// 测试工具：构造一对已完成配对的会话。
func makePair(aAddress: String? = "a@example.com") throws -> (a: TwinSession, b: TwinSession,
                                                              ikA: Curve25519.KeyAgreement.PrivateKey,
                                                              ikB: Curve25519.KeyAgreement.PrivateKey) {
    let ikA = TP.generateX25519()
    let ikB = TP.generateX25519()
    let start = try Handshake.initiatorStart(ik: ikA, address: aAddress)
    let resp = try Handshake.responderComplete(myIK: ikB, scannedQR: start.qr, address: "b@example.com")
    let finish = try Handshake.initiatorComplete(ik: ikA, ek: start.ek,
                                                 sessionID: start.sessionID, myNonce: start.nonce,
                                                 peerQR: resp.myQR)
    let a = TwinSession(material: finish, myIK: ikA, peerIKPub: TP.pubOf(ikB))
    let b = TwinSession(material: resp.material, myIK: ikB, peerIKPub: TP.pubOf(ikA))
    return (a, b, ikA, ikB)
}

final class HandshakeTests: XCTestCase {

    func testBothSidesDeriveIdenticalMaterial() throws {
        let (a, b, _, _) = try makePair()
        XCTAssertEqual(a.material.sessionID, b.material.sessionID)
        XCTAssertEqual(a.material.safetyCodeHex, b.material.safetyCodeHex)
        XCTAssertEqual(a.material.roomID, b.material.roomID)
        XCTAssertEqual(a.ratchet.state.root, b.ratchet.state.root)
        XCTAssertEqual(a.ratchet.state.sendKey, b.ratchet.state.recvKey)   // A 的发送链 = B 的接收链
        XCTAssertEqual(b.ratchet.state.sendKey, a.ratchet.state.recvKey)
        XCTAssertEqual(a.material.peerAddress, "b@example.com")
        XCTAssertEqual(b.material.peerAddress, "a@example.com")
    }

    func testQRCodecRoundTrip() throws {
        let payload = QRPairingPayload(ikPub: TP.randomBytes(32), ekPub: TP.randomBytes(32),
                                       sessionID: TP.randomBytes(16), nonce: TP.randomBytes(16),
                                       address: "someone@example.com")
        let decoded = try QRPairingPayload.decode(payload.encode())
        XCTAssertEqual(decoded.ikPub, payload.ikPub)
        XCTAssertEqual(decoded.address, payload.address)
        XCTAssertEqual(decoded.sessionID, payload.sessionID)

        let noAddr = QRPairingPayload(ikPub: TP.randomBytes(32), ekPub: TP.randomBytes(32),
                                      sessionID: TP.randomBytes(16), nonce: TP.randomBytes(16), address: nil)
        XCTAssertEqual(try QRPairingPayload.decode(noAddr.encode()).address, nil)
    }

    func testQRRejectsWrongSessionID() throws {
        let start = try! handshakeStartPair()
        var tampered = start.respQR
        // 改动 session_id 字段（偏移 69）
        tampered[69] = tampered[69] &+ 1
        let ikA = start.ikA
        XCTAssertThrowsError(try Handshake.initiatorComplete(ik: ikA, ek: start.ek,
                                                             sessionID: start.sessionID,
                                                             myNonce: start.nonce, peerQR: tampered))
    }

    private func handshakeStartPair() throws -> (ikA: Curve25519.KeyAgreement.PrivateKey, ek: Curve25519.KeyAgreement.PrivateKey,
                                                 sessionID: Data, nonce: Data, qr: Data, respQR: Data) {
        let ikA = TP.generateX25519()
        let ikB = TP.generateX25519()
        let start = try Handshake.initiatorStart(ik: ikA, address: nil)
        let resp = try Handshake.responderComplete(myIK: ikB, scannedQR: start.qr, address: nil)
        return (ikA, start.ek, start.sessionID, start.nonce, start.qr, resp.myQR)
    }
}

final class MessagingTests: XCTestCase {

    func testTextRoundTrip() throws {
        let (a, b, _, _) = try makePair()
        let sent = try a.sendText("你好，双栖", timestamp: 1_700_000_000_000)
        XCTAssertEqual(sent.dhStep, 0)
        XCTAssertEqual(sent.chainIndex, 0)
        let out = try b.receive(sent)
        guard case .message(.text(let mid, let body, let ts)) = out else {
            return XCTFail("expected text, got \(out)")
        }
        XCTAssertEqual(body, "你好，双栖")
        XCTAssertEqual(ts, 1_700_000_000_000)
        XCTAssertFalse(mid.isEmpty)
        // B 处理后，其 ACK 捎带在下一条消息里
        let reply = try b.sendText("收到！")
        XCTAssertEqual(reply.chainIndex, 0)
        let back = try a.receive(reply)
        guard case .message(.text(_, let body2, _)) = back else { return XCTFail("expected text") }
        XCTAssertEqual(body2, "收到！")
        XCTAssertEqual(a.myAckedByPeer, 0)   // B 的消息捎带了 ack=0
    }

    func testDuplicateDeliveryIsIgnored() throws {
        let (a, b, _, _) = try makePair()
        let sent = try a.sendText("once")
        XCTAssertNotNil(try b.receive(sent))
        let again = try b.receive(sent)
        guard case .duplicate = again else { return XCTFail("expected duplicate, got \(again)") }
    }

    func testOutOfOrderDelivery() throws {
        let (a, b, _, _) = try makePair()
        let m1 = try a.sendText("one")
        let m2 = try a.sendText("two")
        let m3 = try a.sendText("three")
        // 乱序：先 3，再 1、2
        if case .message(.text(_, let body3, _)) = try b.receive(m3) {
            XCTAssertEqual(body3, "three")
        } else { return XCTFail() }
        if case .message(.text(_, let body1, _)) = try b.receive(m1) {
            XCTAssertEqual(body1, "one")
        } else { return XCTFail() }
        if case .message(.text(_, let body2, _)) = try b.receive(m2) {
            XCTAssertEqual(body2, "two")
        } else { return XCTFail() }
        // 全部处理后跳过表清空
        XCTAssertTrue(b.ratchet.state.skipped.isEmpty)
    }

    func testTamperedEnvelopeFails() throws {
        let (a, b, _, _) = try makePair()
        var sent = try a.sendText("secret")
        sent.ciphertext[10] ^= 0xff
        XCTAssertThrowsError(try b.receive(sent)) { error in
            XCTAssertEqual(error as? TPError, .decryptFailed)
        }
    }

    func testWrongSessionRejected() throws {
        let (a, b, _, _) = try makePair()
        var sent = try a.sendText("x")
        sent.sessionID = TP.randomBytes(16)
        XCTAssertThrowsError(try b.receive(sent))
    }

    func testAckAndReadReceipts() throws {
        let (a, b, _, _) = try makePair()
        let m1 = try a.sendText("hi")
        _ = try b.receive(m1)
        b.markRead()
        let receipt = try b.makeReadReceipt()
        XCTAssertNotNil(receipt)
        if case .message(.receipt(let ack, let read)) = try a.receive(receipt!) {
            XCTAssertEqual(ack, 0)
            XCTAssertEqual(read, 0)
            XCTAssertEqual(a.myAckedByPeer, 0)
            XCTAssertEqual(a.myReadByPeer, 0)
        } else { return XCTFail() }
        // 没有新已读时不再发送回执
        XCTAssertNil(try b.makeReadReceipt())
        XCTAssertNil(try b.makeAck())
    }
}

final class RatchetStepTests: XCTestCase {

    override func setUp() {
        super.setUp()
        TP.ratchetStepMessages = 5   // 测试阈值
    }

    override func tearDown() {
        TP.ratchetStepMessages = 500
        super.tearDown()
    }

    func testInitiatorStepsAtBoundary() throws {
        let (a, b, _, _) = try makePair()
        var last: Envelope?
        for i in 0..<6 {
            last = try a.sendText("msg \(i)")
        }
        // 第 6 条（index 5）触发 step：dh_step=1，携带 ek_pub，index 归零
        XCTAssertEqual(last!.dhStep, 1)
        XCTAssertEqual(last!.chainIndex, 0)
        XCTAssertNotEqual(last!.ekPub, Data(repeating: 0, count: 32))

        let out = try b.receive(last!)
        guard case .message(.text(_, let body, _)) = out else { return XCTFail("got \(out)") }
        XCTAssertEqual(body, "msg 5")
        XCTAssertEqual(b.ratchet.state.recvDhStep, 1)
        XCTAssertEqual(b.ratchet.state.root, a.ratchet.state.root)
    }

    func testBothDirectionsWorkAfterStep() throws {
        let (a, b, _, _) = try makePair()
        // A 发 6 条（第 6 条触发 step）；B 逐条收全（含 carrier）
        for i in 0..<6 {
            let m = try a.sendText("a\(i)")
            if case .message(.text(_, let body, _)) = try b.receive(m) {
                XCTAssertEqual(body, "a\(i)")
            } else { return XCTFail() }
        }
        XCTAssertEqual(b.ratchet.state.recvDhStep, 1)
        // B 在已 reconcile 的新 root 下、用自己的旧发送链回信（step 只影响发起方发送链）
        let earlyReply = try b.sendText("early")
        if case .message(.text(_, let eb, _)) = try a.receive(earlyReply) {
            XCTAssertEqual(eb, "early")
        } else { return XCTFail() }
        // step 后双向继续
        if case .message(.text(_, let rb, _)) = try a.receive(try b.sendText("b after")) {
            XCTAssertEqual(rb, "b after")
        } else { return XCTFail() }
        if case .message(.text(_, let ab, _)) = try b.receive(try a.sendText("a after")) {
            XCTAssertEqual(ab, "a after")
        } else { return XCTFail() }
    }

    func testResponderCannotStepSpontaneously() throws {
        let (a, b, _, _) = try makePair()
        // 响应方未收到 syncRequest 时即使过阈值也不 step
        var sent: Envelope?
        for i in 0..<8 { sent = try b.sendText("b\(i)") }
        XCTAssertEqual(sent!.dhStep, 0)
        XCTAssertEqual(sent!.ekPub, Data(repeating: 0, count: 32))
    }

    func testResyncFlowAfterOverflow() throws {
        let (a, b, _, _) = try makePair()
        TP.skippedKeyCap = 4
        TP.ratchetStepMessages = 1000   // 本测试排除边界 step 干扰
        defer {
            TP.skippedKeyCap = 4096
            TP.ratchetStepMessages = 500
        }
        // A 发 6 条，B 收 m0 和 m5：recvIndex=6，跳过表存 4 条
        var msgs: [Envelope] = []
        for i in 0..<6 { msgs.append(try a.sendText("m\(i)")) }
        _ = try b.receive(msgs[0])
        if case .message(.text(_, let b5, _)) = try b.receive(msgs[5]) {
            XCTAssertEqual(b5, "m5")
        } else { return XCTFail() }
        // 再发 6 条（index 6..11），乱序收 index 11：空洞 5 > cap=4 → 溢出
        for _ in 0..<6 { msgs.append(try a.sendText("m-more")) }
        let outcome = try b.receive(msgs[11])
        guard case .needsResync = outcome else { return XCTFail("got \(outcome)") }
        // B 请求重同步；A 收到后下次发送执行 step
        let syncReq = try b.makeSyncRequest()
        guard case .resyncRequestedByPeer = try a.receive(syncReq) else { return XCTFail() }
        let carrier = try a.sendText("after resync")
        XCTAssertEqual(carrier.dhStep, 1)
        guard case .message(.text(_, let body, _)) = try b.receive(carrier), body == "after resync" else {
            return XCTFail()
        }
        // B 的发送链也重置（resync 流程后 B 的下一条从新链开始）
        let reply = try b.sendText("b back online")
        XCTAssertEqual(reply.dhStep, 0)   // B 的发送链未被 A 的 step 影响，仍是原链继续
        if case .message(.text(_, let rb, _)) = try a.receive(reply) {
            XCTAssertEqual(rb, "b back online")
        } else { return XCTFail() }
    }
}

final class PersistenceTests: XCTestCase {

    func testSessionStateRestore() throws {
        let (a, b, ikA, ikB) = try makePair()
        let m1 = try a.sendText("one")
        let m2 = try a.sendText("two")
        _ = try b.receive(m1)
        let state = try b.exportState()
        let restored = try TwinSession.restore(material: b.material, myIK: ikB,
                                               peerIKPub: b.peerIKPub, stateData: state)
        if case .message(.text(_, let body, _)) = try restored.receive(m2) {
            XCTAssertEqual(body, "two")
        } else { return XCTFail() }
        // 原会话也收 m2，随后两者状态应一致
        _ = try b.receive(m2)
        XCTAssertEqual(restored.ratchet.state, b.ratchet.state)
    }

    func testSkippedKeyCapConstant() {
        XCTAssertEqual(TP.skippedKeyCap, 4096)
    }
}
