import Foundation

/// 传输层抽象（docs/02-传输层抽象.md）。
/// 契约：加密层不感知传输；传输层不感知内容（只见 Envelope 字节）。
/// 投递语义：每方向有序、at-least-once（接收方按链序号去重）、离线信箱 TTL 14 天。

public enum TransportKind: String, Codable, Sendable {
    case email
    case cloudflare
    case portableRelay
}

public enum ConnectionState: String, Sendable {
    case online
    case offline
    case degraded      // 持续失败、退避重连中
}

public struct TransportEnvelope: Sendable {
    /// 传输层消息 ID（UUID，与 Envelope 内的密码层 mid 无关），用于 transport ack / 信箱清理
    public let transportID: String
    /// Envelope 完整字节
    public let data: Data

    public init(transportID: String, data: Data) {
        self.transportID = transportID
        self.data = data
    }
}

public enum TransportEvent: Sendable {
    case envelope(TransportEnvelope)
    case connectionState(ConnectionState)
}

/// 一次性配置凭证。成功 provision 后不得留明文（传输实现自行负责）。
public enum ProvisioningCredential: Sendable {
    case email(EmailAccount)
    case cloudflareRelay(oauthToken: String)          // 用后即焚
    case manualRelay(url: URL, roomKeyBase64: String) // 自托管 relay 手动接入
}

public struct EmailAccount: Sendable {
    public var address: String        // 本方邮箱
    public var authCode: String       // 授权码（QQ/163）/应用专用密码
    public var imapHost: String
    public var imapPort: Int
    public var smtpHost: String
    public var smtpPort: Int

    public init(address: String, authCode: String,
                imapHost: String, imapPort: Int,
                smtpHost: String, smtpPort: Int) {
        self.address = address
        self.authCode = authCode
        self.imapHost = imapHost
        self.imapPort = imapPort
        self.smtpHost = smtpHost
        self.smtpPort = smtpPort
    }
}

/// 传输会话标识：room_id / k_room（加密协议 §8）。
public struct TransportSession: Sendable {
    public let roomID: Data       // 16 字节
    public let authKey: Data      // k_room，HMAC 挑战应答用

    public init(roomID: Data, authKey: Data) {
        self.roomID = roomID
        self.authKey = authKey
    }
}

public protocol RelayTransport: AnyObject, Sendable {
    var kind: TransportKind { get }

    /// 一次性配置：邮箱登录验证 / CF 部署 / 手动 relay。成功后凭证不留明文。
    func provision(_ credential: ProvisioningCredential) async throws

    /// 启动收信循环。推送型实现 = WS 长连；拉取型（邮箱）= IDLE + 轮询。
    func start(session: TransportSession) -> AsyncStream<TransportEvent>

    /// 发送一条 Envelope（传输层自行封装，如 MIME / WS 帧）。
    func send(_ envelope: Data) async throws

    /// 手动拉取积压（推送型实现可为空数组，由 WS 推送覆盖）。
    func fetchPending() async throws -> [TransportEnvelope]

    /// best-effort 传输层回执：服务端/邮箱侧信箱清理。与密码层 ACK 独立。
    func ack(transportIDs: [String]) async

    func stop() async
}

/// 服务商预设（docs/03 §1）。大陆设备默认国内服务商在前。
public struct MailProviderPreset: Sendable {
    public let name: String
    public let imapHost: String
    public let imapPort: Int
    public let smtpHost: String
    public let smtpPort: Int
    /// 是否使用"授权码"而非登录密码（引导文案差异）
    public let usesAuthCode: Bool

    public static let presets: [MailProviderPreset] = [
        .init(name: "QQ 邮箱", imapHost: "imap.qq.com", imapPort: 993,
              smtpHost: "smtp.qq.com", smtpPort: 465, usesAuthCode: true),
        .init(name: "163 邮箱", imapHost: "imap.163.com", imapPort: 993,
              smtpHost: "smtp.163.com", smtpPort: 465, usesAuthCode: true),
        .init(name: "126 邮箱", imapHost: "imap.126.com", imapPort: 993,
              smtpHost: "smtp.126.com", smtpPort: 465, usesAuthCode: true),
        .init(name: "Gmail", imapHost: "imap.gmail.com", imapPort: 993,
              smtpHost: "smtp.gmail.com", smtpPort: 465, usesAuthCode: false),
        .init(name: "Outlook", imapHost: "outlook.office365.com", imapPort: 993,
              smtpHost: "smtp.office365.com", smtpPort: 587, usesAuthCode: false),
        .init(name: "iCloud", imapHost: "imap.mail.me.com", imapPort: 993,
              smtpHost: "smtp.mail.me.com", smtpPort: 587, usesAuthCode: false),
    ]
}
