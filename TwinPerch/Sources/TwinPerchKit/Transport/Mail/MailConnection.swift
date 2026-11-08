import Foundation
import Network

/// 邮件协议的行/字节流抽象：IMAP/SMTP 客户端面向此接口编程，
/// 测试用 ScriptedMailConnection 喂真报文，线上用 TLSMailConnection（实连验证属 Phase 0 人工项）。
public protocol MailConnection: AnyObject, Sendable {
    func connect(host: String, port: Int, tls: Bool) async throws
    /// 发送一行（自动追加 CRLF）
    func sendLine(_ line: String) async throws
    /// 发送原始字节
    func sendRaw(_ data: Data) async throws
    /// 读取一行（去 CRLF；UTF-8 容错）
    func readLine() async throws -> String
    /// 读取精确字节数（IMAP literal 用）
    func readBytes(_ count: Int) async throws -> Data
    func close() async
}

public enum MailConnectionError: Error, Equatable {
    case notConnected
    case connectionClosed
    case timeout
}

// MARK: - 测试/脚本化实现

/// 按脚本顺序回放的假连接。脚本元素：一行响应或原始字节块。
/// 请求方向的内容全部记录在 sentLines / sentRaw 里供断言。
public final class ScriptedMailConnection: MailConnection, @unchecked Sendable {
    public enum ScriptItem {
        case line(String)
        case raw(Data)
    }

    private var script: [ScriptItem]
    public private(set) var sentLines: [String] = []
    public private(set) var sentRaw: [Data] = []
    public private(set) var connected = false
    public private(set) var closedCount = 0
    private let lock = NSLock()

    public init(_ script: [ScriptItem]) {
        self.script = script
    }

    public func connect(host: String, port: Int, tls: Bool) async throws {
        lock.lock(); connected = true; lock.unlock()
    }

    public func sendLine(_ line: String) async throws {
        lock.lock(); sentLines.append(line); lock.unlock()
    }

    public func sendRaw(_ data: Data) async throws {
        lock.lock(); sentRaw.append(data); lock.unlock()
    }

    public func readLine() async throws -> String {
        lock.lock(); defer { lock.unlock() }
        guard case .line(let l)? = script.first else { throw MailConnectionError.connectionClosed }
        script.removeFirst()
        return l
    }

    public func readBytes(_ count: Int) async throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard case .raw(let d)? = script.first, d.count == count else {
            throw MailConnectionError.connectionClosed
        }
        script.removeFirst()
        return d
    }

    public func close() async {
        lock.lock(); closedCount += 1; lock.unlock()
    }
}

// MARK: - 线上实现（Network.framework，TLS）

/// NWConnection 的 async 封装。实连行为（TLS 握手、QQ/163 兼容性）属 Phase 0 人工验证项。
public final class TLSMailConnection: MailConnection, @unchecked Sendable {
    private var connection: NWConnection?
    private let queue = DispatchQueue(label: "app.twinperch.mail")
    private var readBuffer = Data()
    private let bufferLock = NSLock()

    public init() {}

    public func connect(host: String, port: Int, tls: Bool) async throws {
        guard let endpointPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
            throw MailConnectionError.notConnected
        }
        let params: NWParameters = tls ? .tls : .tcp
        let conn = NWConnection(to: .hostPort(host: NWEndpoint.Host(host), port: endpointPort), using: params)
        self.connection = conn
        // 状态回调可能多次触发，continuation 只允许 resume 一次
        let resumed = ResumeOnce()
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.stateUpdateHandler = { [weak resumed] state in
                switch state {
                case .ready:
                    if resumed?.resume() ?? false { cont.resume() }
                case .failed(let error):
                    if resumed?.resume() ?? false { cont.resume(throwing: error) }
                case .cancelled:
                    if resumed?.resume() ?? false { cont.resume(throwing: MailConnectionError.connectionClosed) }
                default: break
                }
            }
            conn.start(queue: self.queue)
        }
    }

    public func sendLine(_ line: String) async throws {
        try await sendRaw(Data((line + "\r\n").utf8))
    }

    public func sendRaw(_ data: Data) async throws {
        guard let conn = connection else { throw MailConnectionError.notConnected }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            })
        }
    }

    public func readLine() async throws -> String {
        // 缓冲里先找 CRLF
        while true {
            bufferLock.lock()
            if let range = readBuffer.range(of: Data([0x0d, 0x0a])) {
                let line = Data(readBuffer[readBuffer.startIndex..<range.lowerBound])
                readBuffer.removeSubrange(readBuffer.startIndex..<range.upperBound)
                bufferLock.unlock()
                return String(decoding: line, as: UTF8.self)
            }
            bufferLock.unlock()
            let chunk = try await readChunk()
            bufferLock.lock()
            readBuffer.append(chunk)
            bufferLock.unlock()
        }
    }

    public func readBytes(_ count: Int) async throws -> Data {
        while true {
            bufferLock.lock()
            if readBuffer.count >= count {
                let out = Data(readBuffer.prefix(count))
                readBuffer.removeSubrange(readBuffer.startIndex..<readBuffer.index(readBuffer.startIndex, offsetBy: count))
                bufferLock.unlock()
                return out
            }
            bufferLock.unlock()
            let chunk = try await readChunk()
            bufferLock.lock()
            readBuffer.append(chunk)
            bufferLock.unlock()
        }
    }

    private func readChunk() async throws -> Data {
        guard let conn = connection else { throw MailConnectionError.notConnected }
        return try await withCheckedThrowingContinuation { cont in
            conn.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, isComplete, error in
                if let error { cont.resume(throwing: error); return }
                if let data, !data.isEmpty { cont.resume(returning: Data(data)); return }
                cont.resume(throwing: MailConnectionError.connectionClosed)
            }
        }
    }

    public func close() async {
        connection?.cancel()
        connection = nil
    }
}

final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    @discardableResult
    func resume() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if done { return false }
        done = true
        return true
    }
}
