import XCTest
@testable import TwinPerchAppCore
@testable import TwinPerchKit

/// 本轮优化项的测试：发件队列、附件分块、重同步提示、门禁、分页、重配对。

/// 可编程成败的假传输
final class StubTransport: RelayTransport, @unchecked Sendable {
    var failNextSends = 0
    private(set) var sent: [Data] = []
    private let lock = NSLock()

    let kind: TransportKind = .portableRelay

    func provision(_ credential: ProvisioningCredential) async throws {}

    func start(session: TransportSession) -> AsyncStream<TransportEvent> {
        AsyncStream { $0.finish() }
    }

    func send(_ envelope: Data) async throws {
        lock.lock()
        if failNextSends > 0 {
            failNextSends -= 1
            lock.unlock()
            throw MailConnectionError.notConnected
        }
        sent.append(envelope)
        lock.unlock()
    }

    func fetchPending() async throws -> [TransportEnvelope] { [] }

    func ack(transportIDs: [String]) async {}

    func stop() async {}
}

@MainActor
final class OptimizationTests: XCTestCase {

    private var tmpDir: URL!

    override func setUp() {
        super.setUp()
        tmpDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tp-opt-\(UUID().uuidString)")
        AppModel.attachmentChunkSize = 512 * 1024
    }

    override func tearDown() {
        AppModel.attachmentChunkSize = 512 * 1024
        try? FileManager.default.removeItem(at: tmpDir)
        super.tearDown()
    }

    private func makeModel(_ name: String) -> AppModel {
        let model = AppModel(keyStore: InMemoryKeyStore())
        model.vaultDirectoryOverride = tmpDir.appendingPathComponent(name)
        return model
    }

    private func pair() throws -> (AppModel, AppModel) {
        let a = makeModel("a")
        let b = makeModel("b")
        let ikA = TP.generateX25519()
        let ikB = TP.generateX25519()
        let start = try Handshake.initiatorStart(ik: ikA, address: "a@qq.com")
        let resp = try Handshake.responderComplete(myIK: ikB, scannedQR: start.qr, address: "b@163.com")
        let finish = try Handshake.initiatorComplete(ik: ikA, ek: start.ek,
                                                     sessionID: start.sessionID,
                                                     myNonce: start.nonce, peerQR: resp.myQR)
        try a.activateForTesting(material: finish, peerIKPub: TP.pubOf(ikB), ik: ikA,
                                 vaultDir: tmpDir.appendingPathComponent("va"))
        try b.activateForTesting(material: resp.material, peerIKPub: TP.pubOf(ikA), ik: ikB,
                                 vaultDir: tmpDir.appendingPathComponent("vb"))
        return (a, b)
    }

    /// 等待异步条件成立（发送走 Task，需轮询）
    private func waitUntil(timeout: TimeInterval = 3, _ cond: @escaping () -> Bool) async {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if cond() { return }
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
    }

    // MARK: - P0 发件队列

    func testSendFailureGoesToOutboxAndRetrySucceeds() async throws {
        let (a, _) = try pair()
        let stub = StubTransport()
        stub.failNextSends = 1
        a.attachTransportForTesting(stub)

        try a.sendText("第一条")
        await waitUntil { a.messages.first?.sendState == .failed }
        XCTAssertEqual(a.messages.first?.sendState, .failed)
        // 发件箱里留了这封信
        let outbox = try a.vault!.outboxItems()
        XCTAssertEqual(outbox.count, 1)
        XCTAssertEqual(outbox[0].preview, "第一条")

        // 恢复后重试成功
        stub.failNextSends = 0
        try a.retrySend(messageID: a.messages.first!.id)
        await waitUntil { a.messages.first?.sendState == .sent }
        XCTAssertEqual(stub.sent.count, 1)
        XCTAssertEqual(try a.vault!.outboxItems().count, 0)
    }

    func testNoTransportFailsImmediatelyNotSilently() throws {
        let (a, _) = try pair()
        try a.sendText("没网也看得见失败")
        XCTAssertEqual(a.messages.first?.sendState, .failed)
        XCTAssertEqual(try a.vault!.outboxItems().count, 1)
    }

    func testOnlineEventTriggersAutoRetry() async throws {
        let (a, b) = try pair()
        // 无传输时发送 → 失败入箱
        try a.sendText("排队中")
        XCTAssertEqual(a.messages.first?.sendState, .failed)

        // 接上传输 → 模拟上线事件触发补发
        let stub = StubTransport()
        a.attachTransportForTesting(stub)
        a.retryPendingOutbox()
        await waitUntil { a.messages.first?.sendState == .sent }
        XCTAssertEqual(stub.sent.count, 1)
        // 对端能解密
        b.ingest(stub.sent[0])
        XCTAssertEqual(b.messages.last?.text, "排队中")
    }

    // MARK: - 附件分块

    func testAttachmentChunkedRoundTrip() async throws {
        AppModel.attachmentChunkSize = 1024   // 强制多块
        let (a, b) = try pair()
        let payload = TP.randomBytes(2500)    // → 3 块

        let aid = "att-1"
        let total = 3
        // A 侧直接走底层分块封装（绕过文件系统，测协议本身）
        for seq in 0..<total {
            let start = seq * 1024
            let end = min(start + 1024, payload.count)
            var dict: [String: CBOR.Value] = [
                "t": .uint(UInt64(Envelope.Kind.manifest.rawValue)),
                "aid": .text(aid),
                "seq": .uint(UInt64(seq)),
                "total": .uint(UInt64(total)),
                "d": .bytes(payload.subdata(in: start..<end)),
                "ts": .uint(1_700_000_000_000),
            ]
            if seq == 0 {
                dict["name"] = .text("photo.png")
                dict["mime"] = .text("image/png")
            }
            let keys = dict.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
            var pairs: [(String, CBOR.Value)] = []
            for k in keys { pairs.append((k, dict[k]!)) }
            let env = try a.session!.sealRaw(kind: .manifest, payloadBytes: CBOR.encode(pairs))
            let bytes = try env.encode()
            let decoded = try Envelope.decode(bytes)
            let outcome = try b.session!.receive(decoded)
            guard case .manifest = outcome else {
                return XCTFail("seq\(seq) 应为 manifest，得到 \(outcome)")
            }
            let fields = try XCTUnwrap(b.session!.lastPayloadCBOR, "seq\(seq) 原始字段缺失")
            try b.ingestAttachmentPayload(fields)
        }

        // 重组完成 → B 收到带附件的消息，内容逐字节一致
        await waitUntil { b.messages.contains { $0.attachment?.name == "photo.png" } }
        let msg = b.messages.first { $0.attachment?.name == "photo.png" }
        XCTAssertNotNil(msg)
        let (meta, data) = try XCTUnwrap(b.attachment(id: msg!.attachment!.fileID))
        XCTAssertEqual(meta.mime, "image/png")
        XCTAssertTrue(meta.isImage)
        XCTAssertEqual(data, payload)
    }

    // MARK: - 解密失败提示与一键重同步

    func testDecryptFailureShowsHintAndSyncRequest() async throws {
        let (a, b) = try pair()
        // 伪造 B 无法解密的密文（用别的会话加密）
        let stranger = TP.generateX25519()
        let key = TP.hkdf(TP.randomBytes(32), info: "x")
        let junk = try TP.seal(Data("x".utf8), encKey: key, nonce: TP.randomBytes(12), aad: Data())
        let env = Envelope(kind: .text, dhStep: 0, chainIndex: 0,
                           sessionID: b.session!.material.sessionID,
                           ekPub: stranger.publicKey.rawRepresentation,
                           rootFP: Data(repeating: 0, count: 4),
                           nonce: TP.randomBytes(12), ciphertext: junk)
        b.ingest(try env.encode())
        // 提示出现（发给陌生链的密文会话内按 decryptFailed 或 invalidInput 处理，均不得静默）
        let hasNotice = b.messages.contains { $0.text.contains("无法解密") || $0.text.contains("重新") }
        XCTAssertTrue(hasNotice || b.lastError != nil, "解密失败必须对用户可见")

        // 一键重同步：hint 清除 + A 收到 syncRequest 后标记 stepRequested（下次发送自动 step）
        try b.sendSyncRequest()
        XCTAssertFalse(b.needsResyncHint)
        let sync = try b.session!.makeSyncRequest()
        a.ingest(try sync.encode())
        XCTAssertTrue(a.ratchetStepRequested())
    }

    // MARK: - 门禁状态机

    func testGatekeeperFlow() async {
        var shouldPass = true
        let gate = Gatekeeper(evaluate: { shouldPass })
        gate.onLaunch()
        XCTAssertEqual(gate.state, .locked)

        await gate.authenticate()
        XCTAssertEqual(gate.state, .unlocked)

        // 退后台 1 秒（< 5 分钟阈值）→ 回前台保持解锁
        gate.backgroundThreshold = 300
        gate.onBackground()
        gate.onForeground()
        XCTAssertEqual(gate.state, .unlocked)

        // 退后台超过阈值 → 回前台锁定，验证失败仍锁
        gate.backgroundThreshold = 0.001
        gate.onBackground()
        try? await Task.sleep(nanoseconds: 5_000_000)
        gate.onForeground()
        XCTAssertEqual(gate.state, .locked)
        shouldPass = false
        await gate.authenticate()
        XCTAssertEqual(gate.state, .locked)
        XCTAssertEqual(gate.lastFailure, "验证未通过")

        // 手动上锁
        shouldPass = true
        await gate.authenticate()
        XCTAssertEqual(gate.state, .unlocked)
        gate.lock()
        XCTAssertEqual(gate.state, .locked)
    }

    // MARK: - 分页

    func testHistoryPagination() throws {
        let (a, b) = try pair()
        // 写入 pageSize+30 条历史
        for i in 0..<(AppModel.pageSize + 30) {
            _ = try b.vault!.appendMessage(timestamp: Int64(1_700_000_000_000 + i),
                                           isOutgoing: false, kind: 0,
                                           body: Data("m\(i)".utf8), meta: Data())
        }
        b.loadHistory()
        XCTAssertEqual(b.messages.count, AppModel.pageSize)
        XCTAssertTrue(b.canLoadOlder)
        XCTAssertEqual(b.messages.first?.text, "m30")   // 最新一页的第一条

        let before = b.messages.count
        b.loadOlderMessages()
        XCTAssertEqual(b.messages.count, before + 30)   // 只剩 30 条更早的
        XCTAssertFalse(b.canLoadOlder)
        XCTAssertEqual(b.messages.first?.text, "m0")
    }

    // MARK: - 重配对

    func testResetPairingClearsSessionButKeepsHistory() throws {
        let (a, b) = try pair()
        let sent = try a.session!.sendText("历史消息", timestamp: 1_700_000_000_000)
        b.ingest(try sent.encode())
        XCTAssertEqual(b.messages.count, 1)
        let oldCode = b.safetyCodeHex

        b.resetPairing()
        XCTAssertNil(b.session)
        XCTAssertEqual(b.messages.count, 0)      // 时间线清空（历史仍在 Vault）
        XCTAssertEqual(b.phase, .fresh)
        // 状态 kv 已置空（下次配对建新会话），历史消息仍在库
        let saved = try b.vault!.value(forKey: AppModel.sessionKey)
        XCTAssertEqual(saved, Data())
        XCTAssertEqual(try b.vault!.messageCount(), 1)
        _ = oldCode
    }
}
