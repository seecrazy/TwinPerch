import Combine
import CryptoKit
import Foundation
import TwinPerchKit

/// App 状态机与编排：
/// 门禁 → 配对（双方互扫）→ 激活（收发 + 发件队列 + 附件 + 本地加密存储）。
/// 发送永不静默失败：先入发件箱，失败标记可重发，恢复在线自动补发。

@MainActor
public final class AppModel: ObservableObject {

    public enum Phase: Equatable {
        case fresh
        case pairingShowMyQR(qrBase64: String)
        case active
    }

    public enum SendState: Equatable {
        case sending
        case sent
        case failed
    }

    public struct AttachmentRef: Equatable {
        public let fileID: String     // 16 字节 hex（Vault attachments 主键）
        public let name: String
        public let isImage: Bool
    }

    public struct ChatMessage: Identifiable, Equatable {
        public let id: String
        public let isOutgoing: Bool
        public let text: String
        public let timestamp: UInt64
        public var read: Bool
        public var sendState: SendState
        public var attachment: AttachmentRef?
    }

    // MARK: - 状态

    @Published public private(set) var phase: Phase = .fresh
    @Published public private(set) var messages: [ChatMessage] = []
    @Published public private(set) var safetyCodeHex: String = ""
    @Published public private(set) var peerAddress: String?
    @Published public private(set) var myAddress: String?
    @Published public var connectionState: ConnectionState = .offline
    @Published public private(set) var lastError: String?
    @Published public private(set) var needsResyncHint = false     // 解密失败 → 建议重同步
    @Published public private(set) var canLoadOlder = false
    @Published public private(set) var transportLabel: String?

    // MARK: - 会话与存储

    public private(set) var session: TwinSession?
    public private(set) var vault: Vault?
    private let keyStore: KeyStore
    private var ik: Curve25519.KeyAgreement.PrivateKey?
    private var pendingInitiatorStart: (ek: Curve25519.KeyAgreement.PrivateKey,
                                        sessionID: Data, nonce: Data, qr: Data)?
    private var transport: RelayTransport?
    private var eventTask: Task<Void, Never>?

    /// 附件重组缓冲（接收方）
    private struct IncomingAttachment {
        var name: String
        var mime: String
        var total: Int
        var received: Data
        var got: Set<Int>
    }
    private var incomingAttachments: [String: IncomingAttachment] = [:]

    public static var attachmentChunkSize = 512 * 1024
    public static let pageSize = 200

    public init(keyStore: KeyStore) {
        self.keyStore = keyStore
    }

    // MARK: - 配对流程

    public func beginPairing(address: String?, isInitiator: Bool) throws -> String {
        let key = ik ?? TP.generateX25519()
        ik = key
        myAddress = address ?? myAddress
        if isInitiator {
            let start = try Handshake.initiatorStart(ik: key, address: address)
            pendingInitiatorStart = start
            let b64 = Data(start.qr).base64EncodedString()
            phase = .pairingShowMyQR(qrBase64: b64)
            return b64
        }
        phase = .pairingShowMyQR(qrBase64: "")
        return ""
    }

    @discardableResult
    public func acceptAsResponder(peerQRBase64: String, address: String?) throws -> String {
        guard let peerQR = Data(base64Encoded: peerQRBase64) else {
            throw TPError.invalidInput
        }
        let key = ik ?? TP.generateX25519()
        ik = key
        myAddress = myAddress ?? address
        let resp = try Handshake.responderComplete(myIK: key, scannedQR: peerQR, address: address)
        let peerPub = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: try QRPairingPayload.decode(peerQR).ikPub)
        try activate(material: resp.material, peerIKPub: peerPub.rawRepresentation)
        let b64 = Data(resp.myQR).base64EncodedString()
        phase = .pairingShowMyQR(qrBase64: b64)
        return b64
    }

    public func completeAsInitiator(peerQRBase64: String) throws {
        guard let peerQR = Data(base64Encoded: peerQRBase64),
              let start = pendingInitiatorStart, let key = ik else {
            throw TPError.invalidInput
        }
        let finish = try Handshake.initiatorComplete(ik: key, ek: start.ek,
                                                     sessionID: start.sessionID,
                                                     myNonce: start.nonce,
                                                     peerQR: peerQR)
        let peerPub = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: try QRPairingPayload.decode(peerQR).ikPub)
        peerAddress = finish.peerAddress
        try activate(material: finish, peerIKPub: peerPub.rawRepresentation)
        phase = .active
    }

    public func finishResponderPairing() {
        phase = .active
    }

    private func activate(material: HandshakeMaterial, peerIKPub: Data) throws {
        guard let key = ik else { throw TPError.invalidInput }
        let vault = try Vault(at: defaultVaultURL, keyStore: keyStore)
        self.vault = vault
        try vault.setKV(Self.peerKeyKey, data: peerIKPub)

        if let saved = try vault.value(forKey: Self.sessionKey), !saved.isEmpty,
           let restored = try? TwinSession.restore(material: material, myIK: key,
                                                   peerIKPub: peerIKPub, stateData: saved) {
            session = restored
        } else {
            let s = TwinSession(material: material, myIK: key, peerIKPub: peerIKPub)
            session = s
            try vault.setKV(Self.sessionKey, data: try s.exportState())
        }
        safetyCodeHex = material.safetyCodeHex
        peerAddress = material.peerAddress
        incomingAttachments = [:]
        needsResyncHint = false
        loadHistory()
    }

    /// 重新配对：尽力通知对方（KEY_NOTICE），会话状态置空（历史消息保留只读）。
    public func resetPairing() {
        if let session, let transport, let notice = try? session.makeKeyNotice() {
            Task { try? await transport.send(try notice.encode()) }
        }
        try? vault?.setKV(Self.sessionKey, data: Data())
        session = nil
        safetyCodeHex = ""
        peerAddress = nil
        pendingInitiatorStart = nil
        incomingAttachments = [:]
        messages = []
        phase = .fresh
    }

    // MARK: - 文本收发（发件队列）

    public func sendText(_ text: String) throws {
        guard let session else { throw TPError.invalidInput }
        let now = TwinSession.nowMillis()
        let envelope = try session.sendText(text, timestamp: now)
        try vault?.setKV(Self.sessionKey, data: try session.exportState())

        let outboxID = try vault?.enqueueOutbox(envelope: try envelope.encode(),
                                                preview: text, createdAt: Int64(now))
        let messageID = (outboxID ?? TP.randomBytes(12)).hex()
        persist(message: ChatMessage(id: messageID, isOutgoing: true,
                                     text: text, timestamp: now, read: false,
                                     sendState: .sending, attachment: nil))
        dispatchOutbox(outboxID: outboxID, messageID: messageID, envelope: envelope)
    }

    /// 重发指定失败消息
    public func retrySend(messageID: String) throws {
        guard let vault,
              let row = try vault.outboxItems().first(where: { $0.id.hex() == messageID }) else {
            throw TPError.invalidInput
        }
        updateMessageState(id: messageID, state: .sending)
        dispatchOutbox(outboxID: row.id, messageID: messageID, envelope: try Envelope.decode(row.envelope))
    }

    /// 全部待发/失败消息补发（恢复在线自动调用）
    public func retryPendingOutbox() {
        guard let vault else { return }
        let rows = (try? vault.outboxItems()) ?? []
        for row in rows where row.state == Vault.outboxPending || row.state == Vault.outboxFailed {
            if let envelope = try? Envelope.decode(row.envelope) {
                updateMessageState(id: row.id.hex(), state: .sending)
                dispatchOutbox(outboxID: row.id, messageID: row.id.hex(), envelope: envelope)
            }
        }
    }

    private func dispatchOutbox(outboxID: Data?, messageID: String, envelope: Envelope) {
        guard let transport else {
            updateMessageState(id: messageID, state: .failed)
            markOutbox(id: outboxID, state: Vault.outboxFailed)
            return
        }
        Task { [weak self] in
            do {
                let bytes = try envelope.encode()
                try await transport.send(bytes)
                await MainActor.run {
                    self?.updateMessageState(id: messageID, state: .sent)
                    if let outboxID { try? self?.vault?.removeOutbox(id: outboxID) }
                }
            } catch {
                await MainActor.run {
                    self?.updateMessageState(id: messageID, state: .failed)
                    if let outboxID {
                        try? self?.vault?.markOutbox(id: outboxID, state: Vault.outboxFailed, incrementAttempts: true)
                    }
                }
            }
        }
    }

    private func updateMessageState(id: String, state: SendState) {
        guard let idx = messages.firstIndex(where: { $0.id == id }) else { return }
        messages[idx].sendState = state
    }

    private func markOutbox(id: Data?, state: Int32) {
        guard let id else { return }
        try? vault?.markOutbox(id: id, state: state, incrementAttempts: true)
    }

    // MARK: - 附件（分块）

    public func sendAttachment(fileURL: URL, name: String, mime: String) throws {
        guard let session, let vault else { throw TPError.invalidInput }
        let data = try Data(contentsOf: fileURL)
        let now = TwinSession.nowMillis()
        let fileID = try vault.saveAttachment(name: name, mime: mime, data: data, timestamp: Int64(now))

        let aid = UUID().uuidString
        let total = max(1, (data.count + Self.attachmentChunkSize - 1) / Self.attachmentChunkSize)
        var envelopes: [Data] = []
        for seq in 0..<total {
            let start = seq * Self.attachmentChunkSize
            let end = min(start + Self.attachmentChunkSize, data.count)
            var payload: [String: CBOR.Value] = [
                "t": .uint(UInt64(Envelope.Kind.manifest.rawValue)),
                "aid": .text(aid),
                "seq": .uint(UInt64(seq)),
                "total": .uint(UInt64(total)),
                "d": .bytes(data.subdata(in: start..<end)),
                "ts": .uint(now),
            ]
            if seq == 0 {
                payload["name"] = .text(name)
                payload["mime"] = .text(mime)
            }
            let keys = payload.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
            var pairs: [(String, CBOR.Value)] = []
            for k in keys { pairs.append((k, payload[k]!)) }
            envelopes.append(try session.sealRaw(kind: .manifest, payloadBytes: CBOR.encode(pairs)).encode())
        }
        try vault.setKV(Self.sessionKey, data: try session.exportState())

        let messageID = UUID().uuidString
        persist(message: ChatMessage(id: messageID, isOutgoing: true,
                                     text: name, timestamp: now, read: true,
                                     sendState: .sending,
                                     attachment: AttachmentRef(fileID: fileID.hex(), name: name,
                                                               isImage: mime.hasPrefix("image/"))))
        Task { [weak self] in
            guard let transport = await self?.transport else {
                await MainActor.run { self?.updateMessageState(id: messageID, state: .failed) }
                return
            }
            for bytes in envelopes {
                do {
                    try await transport.send(bytes)
                } catch {
                    await MainActor.run { self?.updateMessageState(id: messageID, state: .failed) }
                    return
                }
            }
            await MainActor.run { self?.updateMessageState(id: messageID, state: .sent) }
        }
    }

    /// 接收附件分块（session.lastPayloadCBOR 已解出原始字段）
    func ingestAttachmentPayload(_ dict: [String: CBOR.Value]) throws {
        guard let vault else { return }
        guard case .text(let aid)? = dict["aid"],
              case .uint(let seq)? = dict["seq"],
              case .uint(let total)? = dict["total"],
              case .bytes(let chunk)? = dict["d"] else {
            throw TPError.invalidInput
        }
        var entry = incomingAttachments[aid] ?? IncomingAttachment(
            name: "", mime: "application/octet-stream", total: Int(total), received: Data(), got: [])
        if case .text(let n)? = dict["name"] { entry.name = n }
        if case .text(let m)? = dict["mime"] { entry.mime = m }
        entry.got.insert(Int(seq))
        entry.received.append(chunk)
        incomingAttachments[aid] = entry

        if entry.got.count == entry.total {
            incomingAttachments.removeValue(forKey: aid)
            let fileID = try vault.saveAttachment(name: entry.name.isEmpty ? "附件" : entry.name,
                                                  mime: entry.mime, data: entry.received,
                                                  timestamp: Int64(TwinSession.nowMillis()))
            persist(message: ChatMessage(id: aid, isOutgoing: false,
                                         text: entry.name.isEmpty ? "附件" : entry.name,
                                         timestamp: TwinSession.nowMillis(), read: false,
                                         sendState: .sent,
                                         attachment: AttachmentRef(fileID: fileID.hex(),
                                                                   name: entry.name,
                                                                   isImage: entry.mime.hasPrefix("image/"))))
        }
    }

    /// 读取本地附件（聊天 UI 渲染/预览用）
    public func attachment(id fileIDHex: String) throws -> (meta: Vault.AttachmentMeta, data: Data)? {
        guard let vault, let id = Data.fromHex(fileIDHex) else { return nil }
        return try vault.attachment(id: id)
    }

    // MARK: - 入站

    public func ingest(_ data: Data) {
        guard let session else { return }
        guard let envelope = try? Envelope.decode(data) else { return }
        do {
            switch try session.receive(envelope) {
            case .message(.text(let mid, let body, let ts)):
                persist(message: ChatMessage(id: mid.isEmpty ? UUID().uuidString : mid,
                                             isOutgoing: false, text: body,
                                             timestamp: ts, read: false,
                                             sendState: .sent, attachment: nil))
            case .manifest:
                if let dict = session.lastPayloadCBOR {
                    try ingestAttachmentPayload(dict)
                }
            case .message(.keyNotice):
                persist(systemNotice: "对方更换了密钥（安全码已变更）——请当面重新配对验证")
            case .resyncRequestedByPeer:
                break
            case .needsResync:
                needsResyncHint = true
            case .message(.receipt), .duplicate:
                break
            }
            try vault?.setKV(Self.sessionKey, data: try session.exportState())
            refreshReceipts()
        } catch TPError.decryptFailed {
            // 不静默：提示并给出一键重同步
            persist(systemNotice: "收到一条无法解密的消息（可能长时间未同步）")
            needsResyncHint = true
        } catch TPError.sessionDesync {
            persist(systemNotice: "会话出现不可恢复分歧——请当面重新配对")
        } catch {
            lastError = String(describing: error)
        }
    }

    /// 扫码回调分派：已出过码（发起方）→ 收尾握手；否则 → 响应方流程。
    /// iOS 相机扫码与桌面粘贴框共用这一个入口。
    public func ingestPeerQR(_ base64: String) throws {
        if pendingInitiatorStart != nil {
            try completeAsInitiator(peerQRBase64: base64)
        } else {
            _ = try acceptAsResponder(peerQRBase64: base64, address: myAddress)
        }
    }

    /// iOS 壳层回调：APNs token 注册（opt-in 推送）
    public func updateAPNsToken(_ tokenData: Data) async {
        guard let vault else { return }
        let token = tokenData.map { String(format: "%02x", $0) }.joined()
        try? vault.setKV(Self.apnsTokenKey, data: Data(token.utf8))
        let enabled = (try? vault.value(forKey: Self.pushEnabledKey))?.first == 1
        guard enabled,
              let saved = try? vault.value(forKey: Self.proxyURLKey),
              let url = URL(string: String(decoding: saved, as: UTF8.self)) else { return }
        let deviceID = currentDeviceID()
        try? await PushProxyClient(baseURL: url).register(deviceID: deviceID, apnsToken: token)
    }

    private func currentDeviceID() -> String {
        if let saved = try? vault?.value(forKey: Self.deviceIDKey),
           let s = String(data: saved, encoding: .utf8), !s.isEmpty {
            return s
        }
        let id = generateDeviceID()
        try? vault?.setKV(Self.deviceIDKey, data: Data(id.utf8))
        return id
    }

    /// 推送 opt-in 落库与注册（docs/05：代理只见随机 device_id + 计数）
    public func setPushEnabled(_ enabled: Bool, proxyURL: URL) async {
        guard let vault else { return }
        try? vault.setKV(Self.pushEnabledKey, data: Data([enabled ? 1 : 0]))
        try? vault.setKV(Self.proxyURLKey, data: Data(proxyURL.absoluteString.utf8))
        let client = PushProxyClient(baseURL: proxyURL)
        if enabled {
            let deviceID = currentDeviceID()
            if let saved = try? vault.value(forKey: Self.apnsTokenKey),
               let token = String(data: saved, encoding: .utf8) {
                try? await client.register(deviceID: deviceID, apnsToken: token)
            }
            // 尚无 token：等壳层 APNs 回调后由 updateAPNsToken 补注册
        } else {
            try? await client.unregister(deviceID: currentDeviceID())
        }
    }

    /// iOS 后台刷新（BGTask）与回前台补账共用：补发队列 + 拉取积压
    public func backgroundFetch() async {
        guard let transport else { return }
        retryPendingOutbox()
        if let pending = try? await transport.fetchPending() {
            for e in pending { ingest(e.data) }
        }
    }

    /// 一键请求重同步（解密失败提示的按钮动作）
    public func sendSyncRequest() throws {
        guard let session else { throw TPError.invalidInput }
        let sync = try session.makeSyncRequest()
        try vault?.setKV(Self.sessionKey, data: try session.exportState())
        needsResyncHint = false
        Task { try? await transport?.send(try sync.encode()) }
    }

    /// 标记已读并发送回执
    public func markAllRead() throws {
        guard let session, session.ratchet.ackIndex != nil else { return }
        _ = session.markRead()
        if let receipt = try session.makeReadReceipt() {
            try vault?.setKV(Self.sessionKey, data: try session.exportState())
            Task { try? await transport?.send(try receipt.encode()) }
        }
    }

    // MARK: - 传输接入与设置

    /// 邮箱连接（设置页：服务商预设 + 授权码）。provision + 事件接管一体。
    public func connectEmail(account: EmailAccount, peerAddress peer: String?) async throws {
        let t = EmailTransport()
        t.peerAddress = peer
        try await t.provision(.email(account))
        transportLabel = "邮箱 \(account.address)"
        attach(t)
    }

    /// 自托管 / 手动中转连接
    public func connectManualRelay(url: URL) async throws {
        let t = CloudflareTransport()
        t.useRelay(url: url)
        transportLabel = "中转 \(url.host ?? url.absoluteString)"
        attach(t)
    }

    public func disconnectTransport() async {
        await transport?.stop()
        transport = nil
        transportLabel = nil
        connectionState = .offline
    }

    private func attach(_ t: RelayTransport) {
        let ts = try! transportSession()
        transport = t
        eventTask?.cancel()
        let stream = t.start(session: ts)
        eventTask = Task { [weak self] in
            for await event in stream {
                await MainActor.run {
                    switch event {
                    case .envelope(let e): self?.ingest(e.data)
                    case .connectionState(let s):
                        self?.connectionState = s
                        if s == .online { self?.retryPendingOutbox() }
                    }
                }
            }
        }
    }

    // MARK: - 历史与分页

    private var oldestLoadedTimestamp: Int64?

    public func loadHistory() {
        guard let vault else { return }
        let rows = (try? vault.latestMessages(limit: Self.pageSize)) ?? []
        messages = rows.map(Self.chatMessage(from:))
        oldestLoadedTimestamp = rows.first?.timestamp
        canLoadOlder = (try? vault.hasOlderMessages(than: oldestLoadedTimestamp ?? Int64.max)) ?? false
    }

    public func loadOlderMessages() {
        guard let vault, let oldest = oldestLoadedTimestamp else { return }
        let rows = (try? vault.messages(before: oldest, limit: Self.pageSize)) ?? []
        guard !rows.isEmpty else { canLoadOlder = false; return }
        messages.insert(contentsOf: rows.map(Self.chatMessage(from:)), at: 0)
        oldestLoadedTimestamp = rows.first?.timestamp
        canLoadOlder = (try? vault.hasOlderMessages(than: oldestLoadedTimestamp ?? Int64.max)) ?? false
    }

    private static func chatMessage(from row: Vault.MessageRow) -> ChatMessage {
        ChatMessage(id: row.recordID.hex(),
                    isOutgoing: row.isOutgoing,
                    text: String(decoding: row.body, as: UTF8.self),
                    timestamp: UInt64(max(0, row.timestamp)),
                    read: true,
                    sendState: .sent,
                    attachment: nil)
    }

    // MARK: - 持久化

    private func persist(message: ChatMessage) {
        guard let vault else { return }
        _ = try? vault.appendMessage(timestamp: Int64(message.timestamp),
                                     isOutgoing: message.isOutgoing,
                                     kind: Int32(Envelope.Kind.text.rawValue),
                                     body: Data(message.text.utf8),
                                     meta: Data())
        messages.append(message)
    }

    private func persist(systemNotice text: String) {
        guard let vault else { return }
        _ = try? vault.appendMessage(timestamp: Int64(TwinSession.nowMillis()),
                                     isOutgoing: false, kind: -1,
                                     body: Data(text.utf8), meta: Data())
        messages.append(ChatMessage(id: UUID().uuidString, isOutgoing: false,
                                    text: text, timestamp: TwinSession.nowMillis(), read: true,
                                    sendState: .sent, attachment: nil))
    }

    private func refreshReceipts() {
        guard let session, session.myReadByPeer != nil else { return }
        for i in messages.indices where messages[i].isOutgoing && messages[i].sendState == .sent {
            messages[i].read = true
        }
    }

    // MARK: - 辅助

    public static let sessionKey = "tp.session.state"
    public static let peerKeyKey = "tp.session.peer-ik"
    public static let deviceIDKey = "tp.push.device-id"
    public static let apnsTokenKey = "tp.push.apns-token"
    public static let pushEnabledKey = "tp.push.enabled"
    public static let proxyURLKey = "tp.push.proxy-url"

    var vaultDirectoryOverride: URL?

    public var defaultVaultURL: URL {
        if let override = vaultDirectoryOverride {
            return override.appendingPathComponent("vault.db")
        }
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("TwinPerch/vault.db")
    }

    // MARK: - 测试钩子（internal，@testable 可见）

    func activateForTesting(material: HandshakeMaterial, peerIKPub: Data,
                            ik key: Curve25519.KeyAgreement.PrivateKey, vaultDir: URL) throws {
        self.ik = key
        self.vaultDirectoryOverride = vaultDir
        try activate(material: material, peerIKPub: peerIKPub)
    }

    func ratchetStepRequested() -> Bool {
        session?.ratchet.state.stepRequested ?? false
    }

    /// 直接注入传输（测试用，跳过 provision）
    func attachTransportForTesting(_ t: RelayTransport) {
        transport = t
    }

    /// App 内一键部署 Cloudflare 中转（docs/04）：部署 → 写入房间元数据 → 接管连接。
    public func deployRelay(oauthToken: String) async throws -> URL {
        guard let session else { throw TPError.invalidInput }
        let deployer = CloudflareDeployer()
        let result = try await deployer.deploy(oauthToken: oauthToken)
        try await deployer.bootstrapRoom(workerURL: result.workerURL,
                                         deployKey: result.deployKey,
                                         roomID: session.material.roomID,
                                         kRoom: session.material.kRoom,
                                         deviceID: currentDeviceID())
        try await connectManualRelay(url: result.workerURL)
        return result.workerURL
    }

    public func transportSession() throws -> TransportSession {
        guard let session else { throw TPError.invalidInput }
        return TransportSession(roomID: session.material.roomID, authKey: session.material.kRoom)
    }
}

/// 扫码接入点：桌面端无相机（粘贴框），iOS 壳层注入相机扫码。
/// 壳层扫到内容后调 onScanned → AppModel.ingestPeerQR。
public enum QRScannerHook {
    /// 平台具备扫码能力（壳层启动时置 true）
    public static var canScan = false
    /// 壳层注入：弹出扫码界面
    public static var present: (() -> Void)?
    /// 壳层注入：扫到配对码（Base64）
    public static var onScanned: ((String) -> Void)?
}

