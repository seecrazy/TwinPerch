import XCTest
@testable import TwinPerchAppCore
@testable import TwinPerchKit

/// App 编排层测试：不经过传输，直接在两个 AppModel 之间交换 Envelope 字节。
@MainActor
final class AppModelTests: XCTestCase {

    private var tmpDir: URL!

    override func setUp() {
        super.setUp()
        tmpDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tp-appmodel-\(UUID().uuidString)")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tmpDir)
        super.tearDown()
    }

    private func makeModel(_ name: String) -> AppModel {
        let model = AppModel(keyStore: InMemoryKeyStore())
        let dir = tmpDir.appendingPathComponent(name)
        model.vaultDirectoryOverride = dir
        return model
    }

    func testPairingFlowAndMessageExchange() throws {
        // A：发起方出码
        let a = makeModel("a")
        let qrA = try a.beginPairing(address: "a@qq.com", isInitiator: true)
        XCTAssertFalse(qrA.isEmpty)
        guard case .pairingShowMyQR = a.phase else { return XCTFail("phase") }

        // B：扫 A 的码 → 出自己的码
        let b = makeModel("b")
        let qrB = try b.acceptAsResponder(peerQRBase64: qrA, address: "b@163.com")
        XCTAssertFalse(qrB.isEmpty)
        XCTAssertEqual(b.peerAddress, "a@qq.com")

        // A：扫 B 的码 → 完成
        try a.completeAsInitiator(peerQRBase64: qrB)
        guard case .active = a.phase else { return XCTFail("A not active") }
        b.finishResponderPairing()
        XCTAssertEqual(a.peerAddress, "b@163.com")
        XCTAssertEqual(a.safetyCodeHex, b.safetyCodeHex)   // 安全码一致

        // A 发 → B 收（直接喂 envelope 字节）
        let sentA = try a.session!.sendText("晚上吃什么", timestamp: 1_700_000_000_000)
        b.ingest(try sentA.encode())
        XCTAssertEqual(b.messages.last?.text, "晚上吃什么")
        XCTAssertEqual(b.messages.last?.isOutgoing, false)

        // B 回 → A 收
        let sentB = try b.session!.sendText("火锅", timestamp: 1_700_000_001_000)
        a.ingest(try sentB.encode())
        XCTAssertEqual(a.messages.last?.text, "火锅")
        // B 的消息捎带了 ack：A 知道 B 收到了
        XCTAssertEqual(a.session!.myAckedByPeer, 0)
    }

    func testKeyNoticeShowsSystemLine() throws {
        let (a, b, _) = try pairTwoModels()
        let notice = try a.session!.makeKeyNotice()
        b.ingest(try notice.encode())
        XCTAssertEqual(b.messages.last?.text, "对方更换了密钥（安全码已变更）——请当面重新配对验证")
    }

    func testNeedsResyncSendsSyncRequest() throws {
        let (a, b, _) = try pairTwoModels()
        // 模拟 B 收到巨大空洞：直接对 session 注入 skippedStoreOverflow 场景代价高，
        // 改为验证 needsResync 事件路径本身（低层测试已覆盖触发条件）
        let sync = try b.session!.makeSyncRequest()
        a.ingest(try sync.encode())
        XCTAssertEqual(a.ratchetStepRequested(), true)
    }

    func testTransportSessionComposition() throws {
        let (a, b, _) = try pairTwoModels()
        let tsA = try a.transportSession()
        let tsB = try b.transportSession()
        XCTAssertEqual(tsA.roomID, tsB.roomID)          // 同一房间
        XCTAssertNotEqual(tsA.authKey, Data())           // k_room 已派生
    }

    // MARK: - 辅助

    /// 直接用低层握手构造两个模型的会话（绕开 QR 粘贴流程的状态耦合）
    private func pairTwoModels() throws -> (AppModel, AppModel, String) {
        let a = makeModel("pa")
        let b = makeModel("pb")
        let ikA = TP.generateX25519()
        let ikB = TP.generateX25519()
        let start = try Handshake.initiatorStart(ik: ikA, address: "a@qq.com")
        let resp = try Handshake.responderComplete(myIK: ikB, scannedQR: start.qr, address: "b@163.com")
        let finish = try Handshake.initiatorComplete(ik: ikA, ek: start.ek,
                                                     sessionID: start.sessionID,
                                                     myNonce: start.nonce, peerQR: resp.myQR)
        try a.activateForTesting(material: finish,
                                 peerIKPub: TP.pubOf(ikB), ik: ikA, vaultDir: tmpDir.appendingPathComponent("pa"))
        try b.activateForTesting(material: resp.material,
                                 peerIKPub: TP.pubOf(ikA), ik: ikB, vaultDir: tmpDir.appendingPathComponent("pb"))
        return (a, b, finish.safetyCodeHex)
    }
}
