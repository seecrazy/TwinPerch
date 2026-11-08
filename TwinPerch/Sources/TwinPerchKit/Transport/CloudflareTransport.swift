import CryptoKit
import Foundation

/// Cloudflare Worker 传输（docs/04）：海外/进阶选项。WSS 长连 + 服务端离线信箱。
/// 帧协议与 Worker/src/room.ts 对应；本文件实现客户端侧。
/// 实连验证属 Phase 0 人工项；帧编解码与鉴权 MAC 由单测覆盖。

// MARK: - WS 帧编解码（与 room.ts 的 ServerFrame/ClientFrame 对齐）

public enum CFFrame: Equatable, Sendable {
    // Client → Server
    case hello(room: String)
    case auth(macBase64: String)
    case send(id: String, envelopeBase64: String)
    case ack(ids: [String])
    // Server → Client
    case challenge(nBase64: String)
    case ok(backlog: Int)
    case msg(id: String, envelopeBase64: String)
    case bye(reason: String)

    public var encoded: Data {
        let dict: [String: Any] = {
            switch self {
            case .hello(let room):
                return ["t": "hello", "room": room]
            case .auth(let mac):
                return ["t": "auth", "mac": mac]
            case .send(let id, let env):
                return ["t": "send", "id": id, "env": env]
            case .ack(let ids):
                return ["t": "ack", "ids": ids]
            case .challenge(let n):
                return ["t": "challenge", "n": n]
            case .ok(let backlog):
                return ["t": "ok", "backlog": backlog]
            case .msg(let id, let env):
                return ["t": "msg", "id": id, "env": env]
            case .bye(let reason):
                return ["t": "bye", "why": reason]
            }
        }()
        return try! JSONSerialization.data(withJSONObject: dict)
    }

    public static func decode(_ data: Data) -> CFFrame? {
        guard let dict = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let t = dict["t"] as? String else { return nil }
        switch t {
        case "hello":
            guard let room = dict["room"] as? String else { return nil }
            return .hello(room: room)
        case "auth":
            guard let mac = dict["mac"] as? String else { return nil }
            return .auth(macBase64: mac)
        case "send":
            guard let id = dict["id"] as? String, let env = dict["env"] as? String else { return nil }
            return .send(id: id, envelopeBase64: env)
        case "ack":
            guard let ids = dict["ids"] as? [String] else { return nil }
            return .ack(ids: ids)
        case "challenge":
            guard let n = dict["n"] as? String else { return nil }
            return .challenge(nBase64: n)
        case "ok":
            guard let backlog = dict["backlog"] as? Int else { return nil }
            return .ok(backlog: backlog)
        case "msg":
            guard let id = dict["id"] as? String, let env = dict["env"] as? String else { return nil }
            return .msg(id: id, envelopeBase64: env)
        case "bye":
            return .bye(reason: dict["why"] as? String ?? "")
        default:
            return nil
        }
    }
}

public enum CFTransportError: Error, Equatable {
    case badFrame
    case authFailed
    case notProvisioned
}

/// 鉴权 MAC：HMAC-SHA256(k_room, challenge_bytes) 的 Base64（Worker room.ts verifyAuth 对应）
public enum CFAuth {
    public static func mac(authKey: Data, challengeBase64: String) -> String? {
        guard let challenge = Data(base64Encoded: challengeBase64) else { return nil }
        let mac = TP.hmac(authKey, challenge)
        return mac.base64EncodedString()
    }
}

// MARK: - 传输实现

public final class CloudflareTransport: @unchecked Sendable, RelayTransport {
    public let kind: TransportKind = .cloudflare

    private let lock = NSLock()
    private var relayBaseURL: URL?
    private var task: URLSessionWebSocketTask?
    private var continuation: AsyncStream<TransportEvent>.Continuation?
    private var pollTask: Task<Void, Never>?
    private var currentSession: TransportSession?
    private var authenticated = false
    private let urlSession: URLSession

    public init(urlSession: URLSession = .shared) {
        self.urlSession = urlSession
    }

    // MARK: - RelayTransport

    /// 部署由 CloudflareDeployer 完成；本方法接收已部署的中转 URL 作为"凭证"，
    /// OAuth token 流程在 App 层组合（token 用后即焚，不落库）。
    public func provision(_ credential: ProvisioningCredential) async throws {
        switch credential {
        case .cloudflareRelay(let token):
            let deployer = CloudflareDeployer()
            let result = try await deployer.deploy(oauthToken: token)
            useRelay(url: result.workerURL)
        case .manualRelay(let url, _):
            useRelay(url: url)
        default:
            throw CFTransportError.notProvisioned
        }
    }

    /// 手动注入已部署的中转地址（App 部署流完成后调用）
    public func useRelay(url: URL) {
        lock.lock(); relayBaseURL = url; lock.unlock()
    }

    public func start(session: TransportSession) -> AsyncStream<TransportEvent> {
        AsyncStream { cont in
            lock.lock()
            self.continuation = cont
            self.currentSession = session
            lock.unlock()
            let task = Task {
                await self.runLoop(session: session)
            }
            cont.onTermination = { _ in task.cancel() }
            lock.lock()
            self.pollTask = task
            lock.unlock()
        }
    }

    public func send(_ envelope: Data) async throws {
        let id = UUID().uuidString
        let frame = CFFrame.send(id: id, envelopeBase64: envelope.base64EncodedString())
        guard let wsTask = task else { throw CFTransportError.notProvisioned }
        try await wsTask.send(.string(String(decoding: frame.encoded, as: UTF8.self)))
    }

    public func fetchPending() async throws -> [TransportEnvelope] {
        []   // 推送型：由 WS 重放 backlog 覆盖
    }

    public func ack(transportIDs: [String]) async {
        let frame = CFFrame.ack(ids: transportIDs)
        try? await task?.send(.string(String(decoding: frame.encoded, as: UTF8.self)))
    }

    public func stop() async {
        let t: URLSessionWebSocketTask? = lock.withLock {
            pollTask?.cancel()
            pollTask = nil
            continuation?.finish()
            continuation = nil
            authenticated = false
            return task
        }
        t?.cancel(with: .normalClosure, reason: nil)
    }

    // MARK: - WS 循环

    private func runLoop(session: TransportSession) async {
        var backoff: UInt64 = 1_000_000_000
        while !Task.isCancelled {
            guard let base = relayBaseURL else {
                yield(.connectionState(.offline))
                try? await Task.sleep(nanoseconds: backoff)
                continue
            }
            var components = URLComponents(url: base.appendingPathComponent("ws"), resolvingAgainstBaseURL: false)!
            components.queryItems = [URLQueryItem(name: "room", value: session.roomID.hex())]
            let wsTask = urlSession.webSocketTask(with: components.url!)
            lock.withLock {
                self.task = wsTask
                self.authenticated = false
            }
            wsTask.resume()
            yield(.connectionState(.online))

            // 收信循环
            await receiveLoop(task: wsTask, session: session)
            // 连接断开 → 退避重连
            yield(.connectionState(.degraded))
            try? await Task.sleep(nanoseconds: backoff)
            backoff = min(backoff * 2, 64_000_000_000)
        }
    }

    private func receiveLoop(task: URLSessionWebSocketTask, session: TransportSession) async {
        while !Task.isCancelled {
            let message: URLSessionWebSocketTask.Message
            do {
                message = try await webSocketReceive(task)
            } catch {
                return   // 断线，外层重连
            }
            switch message {
            case .string(let text):
                guard let frame = CFFrame.decode(Data(text.utf8)) else { continue }
                await handle(frame: frame, task: task, session: session)
            case .data(let data):
                if let frame = CFFrame.decode(data) {
                    await handle(frame: frame, task: task, session: session)
                }
            @unknown default:
                return
            }
        }
    }

    private func handle(frame: CFFrame, task: URLSessionWebSocketTask, session: TransportSession) async {
        switch frame {
        case .challenge(let n):
            guard let mac = CFAuth.mac(authKey: session.authKey, challengeBase64: n) else {
                yield(.connectionState(.offline))
                return
            }
            _ = try? await task.send(.string(String(decoding: CFFrame.hello(room: session.roomID.hex()).encoded, as: UTF8.self)))
            _ = try? await task.send(.string(String(decoding: CFFrame.auth(macBase64: mac).encoded, as: UTF8.self)))
        case .ok(let backlog):
            lock.withLock { authenticated = true }
            yield(.connectionState(.online))
            _ = backlog   // 重放由随后的 msg 帧完成
        case .msg(let id, let env):
            guard let data = Data(base64Encoded: env) else { return }
            yield(.envelope(TransportEnvelope(transportID: id, data: data)))
        case .bye:
            yield(.connectionState(.offline))
            task.cancel(with: .normalClosure, reason: nil)
        default:
            break
        }
    }

    private func webSocketReceive(_ task: URLSessionWebSocketTask) async throws -> URLSessionWebSocketTask.Message {
        try await withCheckedThrowingContinuation { cont in
            task.receive { result in
                switch result {
                case .success(let m): cont.resume(returning: m)
                case .failure(let e): cont.resume(throwing: e)
                }
            }
        }
    }

    private func yield(_ event: TransportEvent) {
        let cont = lock.withLock { continuation }
        cont?.yield(event)
    }
}
