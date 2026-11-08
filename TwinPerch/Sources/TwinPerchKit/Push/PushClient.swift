import Foundation

/// 推送代理客户端（docs/05）：opt-in。代理只收到随机 device_id + 计数。
public struct PushProxyClient: Sendable {
    public let baseURL: URL

    public init(baseURL: URL) {
        self.baseURL = baseURL
    }

    /// 开启"即时提醒"：注册 device_id → APNs token 映射
    public func register(deviceID: String, apnsToken: String) async throws {
        try await post("/register", body: [
            "device_id": deviceID,
            "apns_token": apnsToken,
            "kind": "ios",
        ])
    }

    /// 关闭"即时提醒"
    public func unregister(deviceID: String) async throws {
        try await post("/unregister", body: ["device_id": deviceID])
    }

    private func post(_ path: String, body: [String: Any]) async throws {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "content-type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (_, resp) = try await URLSession.shared.data(for: request)
        guard (resp as? HTTPURLResponse)?.statusCode == 200 else {
            throw PushError.proxyRejected
        }
    }
}

public enum PushError: Error, Equatable {
    case proxyRejected
}

/// 生成随机 device_id（128-bit hex，格式由代理校验）
public func generateDeviceID() -> String {
    TP.randomBytes(16).hex()
}
