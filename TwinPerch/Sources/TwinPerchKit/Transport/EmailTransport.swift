import Foundation

/// 邮箱传输（docs/03）：主干实现。密文作为 MIME 附件收发于专用文件夹 `TwinPerch`，
/// ACK 后从服务器删除（"信箱清空"承诺；保留副本为可选项）。
/// 收信：前台 IDLE + 轮询；发信：SMTP 一条一封。
/// 实连验证（QQ/163 后台行为）属 Phase 0 人工项；协议逻辑由脚本化连接单测覆盖。

public final class EmailTransport: @unchecked Sendable, RelayTransport {
    public let kind: TransportKind = .email

    private let folderName: String
    private let lock = NSLock()
    private var account: EmailAccount?
    private var imap: IMAPClient?
    private var pollTask: Task<Void, Never>?
    private var continuation: AsyncStream<TransportEvent>.Continuation?
    /// transportID → IMAP UID（用于 ack 删信）
    private var pendingUIDs: [String: UInt32] = [:]
    private var connected = false
    /// 已发出 transportID 集合（发信后回执用）
    private var sentIDs: Set<String> = []

    /// 连接工厂（测试可注入脚本化连接；线上默认 TLS）
    private let makeIMAPConnection: @Sendable () -> MailConnection
    private let makeSMTPConnection: @Sendable () -> MailConnection

    public init(folderName: String = "TwinPerch",
                makeIMAPConnection: @escaping @Sendable () -> MailConnection = { TLSMailConnection() },
                makeSMTPConnection: @escaping @Sendable () -> MailConnection = { TLSMailConnection() }) {
        self.folderName = folderName
        self.makeIMAPConnection = makeIMAPConnection
        self.makeSMTPConnection = makeSMTPConnection
    }

    // MARK: - RelayTransport

    public func provision(_ credential: ProvisioningCredential) async throws {
        guard case .email(let acct) = credential else {
            throw IMAPError.serverError("credential mismatch")
        }
        let imap = IMAPClient(connection: makeIMAPConnection())
        try await imap.connect(host: acct.imapHost, port: acct.imapPort, tls: true)
        try await imap.readGreeting()
        try await imap.login(user: acct.address, password: acct.authCode)
        try await imap.ensureFolder(folderName)
        try await imap.selectFolder(folderName)
        lock.withLock {
            self.account = acct
            self.imap = imap
            self.connected = true
        }
    }

    public func start(session: TransportSession) -> AsyncStream<TransportEvent> {
        AsyncStream { cont in
            let wasOnline = lock.withLock { self.connected }
            cont.yield(.connectionState(wasOnline ? .online : .offline))
            let task = Task {
                await self.pollLoop()
            }
            cont.onTermination = { _ in
                task.cancel()
            }
            lock.withLock {
                self.continuation = cont
                self.pollTask = task
            }
        }
    }

    public func send(_ envelope: Data) async throws {
        guard let acct = account else { throw MailConnectionError.notConnected }
        let transportID = UUID().uuidString
        guard let peer = peerAddress else { throw MailConnectionError.notConnected }
        let message = TwinMessage(from: acct.address, to: peer, transportID: transportID, payload: envelope)
        let mime = MIME.encode(message)
        let smtp = SMTPClient(connection: makeSMTPConnection())
        try await smtp.send(from: acct.address, to: peer,
                            authUser: acct.address, authPassword: acct.authCode,
                            data: mime)
        lock.withLock { sentIDs.insert(transportID) }
    }

    public func fetchPending() async throws -> [TransportEnvelope] {
        try await fetchOnce()
    }

    public func ack(transportIDs: [String]) async {
        guard let imap = imap else { return }
        let uids: [UInt32] = lock.withLock {
            var acc: [UInt32] = []
            for id in transportIDs {
                if let uid = pendingUIDs.removeValue(forKey: id) { acc.append(uid) }
            }
            return acc
        }
        guard !uids.isEmpty else { return }
        for uid in uids {
            try? await imap.markDeleted(uid: uid)
        }
        try? await imap.expunge()
    }

    public func stop() async {
        let task: Task<Void, Never>? = lock.withLock {
            let t = pollTask
            pollTask = nil
            continuation?.finish()
            continuation = nil
            connected = false
            return t
        }
        task?.cancel()
        try? await imap?.logout()
    }

    // MARK: - 内部

    /// 对方地址（配对时经 QR 交换）
    public var peerAddress: String?

    private func yield(_ event: TransportEvent) {
        let cont = lock.withLock { continuation }
        cont?.yield(event)
    }

    /// 收信轮询主循环：立即补账一次 → IDLE 等通知 → 有通知再拉取。
    private func pollLoop() async {
        while !Task.isCancelled {
            do {
                _ = try await fetchOnce()
                yield(.connectionState(.online))
            } catch {
                yield(.connectionState(.degraded))
                // 指数退避重连（docs/02 §4）
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                if let acct = account {
                    let imap = IMAPClient(connection: makeIMAPConnection())
                    try? await imap.connect(host: acct.imapHost, port: acct.imapPort, tls: true)
                    try? await imap.readGreeting()
                    try? await imap.login(user: acct.address, password: acct.authCode)
                    try? await imap.ensureFolder(folderName)
                    try? await imap.selectFolder(folderName)
                    lock.withLock { self.imap = imap }
                }
                continue
            }
            let imap = lock.withLock { self.imap }
            guard let imap else { break }
            do {
                let gotMail = try await imap.idle(timeout: 25 * 60)
                if !gotMail {
                    // 超时也拉一次（服务器可能漏通知）
                    _ = try? await fetchOnce()
                }
            } catch {
                yield(.connectionState(.offline))
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    /// 拉取全部未读 → 解析 MIME → 上抛 envelope 事件（密码层负责去重）
    private func fetchOnce() async throws -> [TransportEnvelope] {
        let imap = lock.withLock { self.imap }
        guard let imap else { throw MailConnectionError.notConnected }
        let uids = try await imap.searchUnseen()
        var out: [TransportEnvelope] = []
        for uid in uids {
            let (_, mimeData) = try await imap.fetchMessage(uid: uid)
            let message = try MIME.decode(mimeData)
            lock.withLock { pendingUIDs[message.transportID] = uid }
            out.append(TransportEnvelope(transportID: message.transportID, data: message.payload))
            yield(.envelope(TransportEnvelope(transportID: message.transportID, data: message.payload)))
        }
        return out
    }
}
