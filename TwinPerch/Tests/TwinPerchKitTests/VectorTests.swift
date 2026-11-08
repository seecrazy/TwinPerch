import CryptoKit
import XCTest
@testable import TwinPerchKit

/// TP-Crypt v1 交叉验证：加载 Python 参考实现生成的向量，
/// 对握手派生物、每条 envelope 的完整字节、最终链状态做逐字节断言。
final class VectorTests: XCTestCase {

    func loadVectors() throws -> (inputs: [String: String], stepEks: [String],
                                          handshake: [String: String], v: [String: Any]) {
        let url = Bundle.module.url(forResource: "vectors", withExtension: "json", subdirectory: "Fixtures")
            ?? Bundle.module.url(forResource: "vectors", withExtension: "json")
        let data = try Data(contentsOf: XCTUnwrap(url, "vectors.json not found in test bundle"))
        let v = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let inputsAny = try XCTUnwrap(v["inputs"] as? [String: Any])
        var inputs = [String: String]()
        for (k, val) in inputsAny { if let s = val as? String { inputs[k] = s } }
        let stepEks = try XCTUnwrap(inputsAny["step_eks"] as? [Any]).map { try XCTUnwrap($0 as? String) }
        let hs = try XCTUnwrap(v["handshake"] as? [String: String])
        return (inputs, stepEks, hs, v)
    }

    /// 构建一对由向量固定输入决定的对等会话。
    /// 前置条件：测试层已把 TP.randomProvider 设为含 [ek_a, sid, nonce_a, ek_b, nonce_b, step_ek] 的队列，
    /// 且在消息循环结束前不得清除（step EK 在 i=500 才被消费）。
    func makeVectorPair(inputs: [String: String], handshake: [String: String]) throws -> (a: TwinSession, b: TwinSession) {
        let ikA = try TP.x25519(raw: Data.fromHex(inputs["ik_a"]!)!)
        let ikB = try TP.x25519(raw: Data.fromHex(inputs["ik_b"]!)!)
        let start = try Handshake.initiatorStart(ik: ikA, address: nil)
        let resp = try Handshake.responderComplete(myIK: ikB, scannedQR: start.qr, address: nil)
        let finish = try Handshake.initiatorComplete(ik: ikA, ek: start.ek,
                                                     sessionID: start.sessionID,
                                                     myNonce: start.nonce, peerQR: resp.myQR)
        XCTAssertEqual(finish.master.hex(), handshake["master"], "master")
        XCTAssertEqual(finish.root.hex(), handshake["root"], "root")
        XCTAssertEqual(finish.kRoom.hex(), handshake["k_room"], "k_room")
        XCTAssertEqual(finish.roomID.hex(), handshake["room_id"], "room_id")
        XCTAssertEqual(finish.kConfirm.hex(), handshake["k_confirm"], "k_confirm")
        XCTAssertEqual(finish.safetyCodeHex, handshake["safety"], "safety")
        let a = TwinSession(material: finish, myIK: ikA, peerIKPub: TP.pubOf(ikB))
        let b = TwinSession(material: resp.material, myIK: ikB, peerIKPub: TP.pubOf(ikA))
        XCTAssertEqual(a.ratchet.state.sendKey.hex(), handshake["seed_a"], "A 发送链种子 = chain-a")
        XCTAssertEqual(b.ratchet.state.sendKey.hex(), handshake["seed_b"], "B 发送链种子 = chain-b")
        XCTAssertEqual(a.ratchet.state.sendKey.hex(), b.ratchet.state.recvKey.hex())
        return (a, b)
    }

    func testCrossValidationWithPythonReference() throws {
        let (inputs, stepEks, hs, v) = try loadVectors()
        let queue = try QueueRandom(hex: [
            inputs["ek_a"]!, inputs["sid"]!, inputs["nonce_a"]!,
            inputs["ek_b"]!, inputs["nonce_b"]!, stepEks.first!
        ])
        TP.randomProvider = { queue.next($0) }
        defer { TP.randomProvider = nil }
        let (a, b) = try makeVectorPair(inputs: inputs, handshake: hs)

        // A → B：502 条，含 index 500 处的一次 DH 重键
        let aMsgs = try XCTUnwrap(v["a_messages"] as? [[String: Any]])
        XCTAssertEqual(aMsgs.count, 502)
        for m in aMsgs {
            let i = try XCTUnwrap(m["i"] as? Int)
            let plaintext = try XCTUnwrap(m["plaintext"] as? String)
            let payload = Envelope.Payload(kind: .text, body: plaintext,
                                           timestamp: UInt64(1_700_000_000_000 + i))
            let env = try a.sealEnvelope(kind: .text, payload: payload)
            XCTAssertEqual(try env.encode().hex(), m["envelope"] as? String, "envelope bytes, i=\(i)")
            let out = try b.receive(env)
            guard case .message(.text(_, let body, _)) = out, body == plaintext else {
                return XCTFail("B failed to decrypt i=\(i): \(out)")
            }
        }
        XCTAssertEqual(a.ratchet.state.sendDhStep, 1, "A 应在 index 500 处执行过一次重键")
        XCTAssertEqual(b.ratchet.state.recvDhStep, 1)

        // B → A：2 条文本 + 1 条 ACK
        let bMsgs = try XCTUnwrap(v["b_messages"] as? [[String: Any]])
        for m in bMsgs {
            let i = try XCTUnwrap(m["i"] as? Int)
            let plaintext = try XCTUnwrap(m["plaintext"] as? String)
            let env: Envelope
            if i < 2 {
                let payload = Envelope.Payload(kind: .text, body: plaintext,
                                               timestamp: UInt64(1_700_000_100_000 + i))
                env = try b.sealEnvelope(kind: .text, payload: payload)
            } else {
                env = try b.sealEnvelope(kind: .ack,
                                         payload: Envelope.Payload(kind: .ack, ackIndex: 501))
            }
            XCTAssertEqual(try env.encode().hex(), m["envelope"] as? String, "envelope bytes, b\(i)")
            _ = try a.receive(env)
        }

        // 最终链状态逐字节对拍
        let fs = try XCTUnwrap(v["final_state"] as? [String: Any])
        XCTAssertEqual(a.ratchet.state.sendKey.hex(), fs["a_send_key"] as? String, "a_send_key")
        XCTAssertEqual(Int(a.ratchet.state.sendIndex), fs["a_send_index"] as? Int, "a_send_index")
        XCTAssertEqual(Int(a.ratchet.state.sendDhStep), fs["a_send_dh_step"] as? Int, "a_send_dh_step")
        XCTAssertEqual(a.ratchet.state.recvKey.hex(), fs["b_send_key"] as? String, "A 的接收链 = B 的发送链状态")
        XCTAssertEqual(Int(a.ratchet.state.recvIndex), fs["b_send_index"] as? Int, "A 的接收进度 = B 的发送进度")
        XCTAssertEqual(b.ratchet.state.recvKey.hex(), fs["b_recv_key"] as? String, "b_recv_key")
        XCTAssertEqual(Int(b.ratchet.state.recvIndex), fs["b_recv_index"] as? Int, "b_recv_index")
        XCTAssertEqual(Int(b.ratchet.state.recvDhStep), fs["b_recv_dh_step"] as? Int, "b_recv_dh_step")
        XCTAssertEqual(b.ratchet.state.sendKey.hex(), fs["b_send_key"] as? String, "b_send_key")
        XCTAssertEqual(Int(b.ratchet.state.sendIndex), fs["b_send_index"] as? Int, "b_send_index")
        XCTAssertEqual(Int(b.ratchet.state.skipped.count), fs["b_skipped_count"] as? Int, "b_skipped_count")
    }

    /// 乱序消费：用同一批向量在新会话上乱序投递
    func testVectorsOutOfOrderOnFreshSession() throws {
        let (inputs, stepEks, hs, v) = try loadVectors()
        let queue = try QueueRandom(hex: [
            inputs["ek_a"]!, inputs["sid"]!, inputs["nonce_a"]!,
            inputs["ek_b"]!, inputs["nonce_b"]!, stepEks.first!
        ])
        TP.randomProvider = { queue.next($0) }
        defer { TP.randomProvider = nil }
        let (_, b) = try makeVectorPair(inputs: inputs, handshake: hs)

        let aMsgs = try XCTUnwrap(v["a_messages"] as? [[String: Any]])
        // 乱序窗口只能在同一链内：一旦收到 step-1 消息，step-0 链即前向保密销毁，
        // 旧链消息永久不可解密（FS 属性，不是 bug）。故先乱序收完 step 0，再收 step 1。
        let order = [4, 0, 3, 1, 2] + Array(5..<500) + [500, 501]
        XCTAssertEqual(order.count, aMsgs.count)
        for i in order {
            let env = try Envelope.decode(Data.fromHex(aMsgs[i]["envelope"] as! String)!)
            let out = try b.receive(env)
            guard case .message(.text(_, let body, _)) = out,
                  body == (aMsgs[i]["plaintext"] as? String) else {
                return XCTFail("out-of-order decrypt failed at \(i)")
            }
        }
        // step 后接收进度按新链重新计数：2 条 step-1 消息 → index 2
        XCTAssertEqual(b.ratchet.state.recvIndex, 2)
        XCTAssertEqual(b.ratchet.state.recvDhStep, 1)
    }
}

/// 乱序跨 step：先收 step-1 再收 step-0 → 旧链消息不可解密（FS 属性验证）
final class ForwardSecrecyTests: XCTestCase {

    func testOldChainUndecryptableAfterStep() throws {
        let vt = VectorTests()
        let (inputs, stepEks, hs, v) = try vt.loadVectors()
        let queue = try QueueRandom(hex: [
            inputs["ek_a"]!, inputs["sid"]!, inputs["nonce_a"]!,
            inputs["ek_b"]!, inputs["nonce_b"]!, stepEks.first!
        ])
        TP.randomProvider = { queue.next($0) }
        defer { TP.randomProvider = nil }
        let (_, b) = try vt.makeVectorPair(inputs: inputs, handshake: hs)
        let aMsgs = try XCTUnwrap(v["a_messages"] as? [[String: Any]])

        // 先收 step-1 的两条
        for i in [500, 501] {
            let env = try Envelope.decode(Data.fromHex(aMsgs[i]["envelope"] as! String)!)
            _ = try b.receive(env)
        }
        // 再收 step-0 的旧消息：应被判定为 duplicate（不可解密）
        let old = try Envelope.decode(Data.fromHex(aMsgs[42]["envelope"] as! String)!)
        let outcome = try b.receive(old)
        guard case .duplicate = outcome else {
            return XCTFail("step-0 消息在 reconcile 后应不可解密，got \(outcome)")
        }
    }
}

/// 从固定十六进制序列按序取字节的确定性随机源。
final class QueueRandom {
    private var data: Data

    init(hex: [String]) throws {
        data = Data()
        for h in hex {
            guard let d = Data.fromHex(h) else { throw TPError.invalidInput }
            data.append(d)
        }
    }

    func next(_ n: Int) -> Data {
        let d = data.prefix(n)
        data = data.count > n ? data.subdata(in: n..<data.count) : Data()
        return Data(d)
    }
}
