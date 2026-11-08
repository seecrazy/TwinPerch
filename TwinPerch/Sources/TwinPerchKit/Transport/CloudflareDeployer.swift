import Foundation

/// Cloudflare 部署客户端（docs/04 §4）。
/// 流程：OAuth token（App 层经 ASWebAuthenticationSession 获取）→ 列账户 →
/// 上传 Worker（multipart，含 DO migration）→ 启用 workers.dev 子域 →
/// POST /bootstrap 写入 k_room（DEPLOY_KEY 防护）→ 返回中转 URL。
/// OAuth token 用后即焚：本类型不持久化任何凭证。
/// 实连验证属 Phase 0 人工项；本文件仅结构化 API 调用。

public struct DeployResult: Sendable {
    public let accountID: String
    /// https://twinperch-relay.<用户子域>.workers.dev
    public let workerURL: URL
    /// 本次部署生成的密钥（写入 room 元数据与 Worker env），App 存 Vault
    public let deployKey: String
}

public enum DeployError: Error, Equatable {
    case apiError(String)
    case noAccount
    case badResponse
}

public struct CloudflareDeployer: Sendable {
    /// Worker 脚本内容（编译后的 JS 模块）。App 打包管线负责把 Worker/ 编译产物带入。
    public var scriptContent: String

    public init(scriptContent: String = TwinPerchRelayScript.content) {
        self.scriptContent = scriptContent
    }

    public static let scriptName = "twinperch-relay"

    // MARK: - 部署主流程

    public func deploy(oauthToken: String) async throws -> DeployResult {
        let accountID = try await firstAccount(oauthToken: oauthToken)
        try await uploadScript(accountID: accountID, oauthToken: oauthToken)
        let workerURL = try await enableSubdomain(accountID: accountID, oauthToken: oauthToken)
        let deployKey = TP.randomBytes(24).hex()
        return DeployResult(accountID: accountID, workerURL: workerURL, deployKey: deployKey)
    }

    /// 部署完成后写入房间元数据（k_room + 推送 device_id），供 DO 鉴权与 opt-in 推送使用
    public func bootstrapRoom(workerURL: URL, deployKey: String,
                              roomID: Data, kRoom: Data,
                              deviceID: String?) async throws {
        var body: [String: Any] = [
            "room": roomID.hex(),
            "k_room": kRoom.base64EncodedString(),
        ]
        if let deviceID { body["device_id"] = deviceID }
        var request = URLRequest(url: workerURL.appendingPathComponent("bootstrap"))
        request.httpMethod = "POST"
        request.setValue(deployKey, forHTTPHeaderField: "x-tp-deploy-key")
        request.setValue("application/json", forHTTPHeaderField: "content-type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp) = try await URLSession.shared.data(for: request)
        guard (resp as? HTTPURLResponse)?.statusCode == 200 else {
            throw DeployError.apiError(String(decoding: data, as: UTF8.self))
        }
    }

    // MARK: - Cloudflare API

    private func firstAccount(oauthToken: String) async throws -> String {
        let json = try await apiGET("https://api.cloudflare.com/client/v4/accounts", token: oauthToken)
        guard let result = json["result"] as? [[String: Any]],
              let id = result.first?["id"] as? String else {
            throw DeployError.noAccount
        }
        return id
    }

    /// PUT /accounts/{id}/workers/scripts/{name}：multipart（metadata + main module）
    /// metadata 含 new_sqlite_classes migration 与 DO binding（免费层必需）
    func uploadScript(accountID: String, oauthToken: String) async throws {
        let metadata: [String: Any] = [
            "main_module": "worker.js",
            "compatibility_date": "2025-04-01",
            "bindings": [
                ["type": "durable_object_namespace", "name": "ROOM", "class_name": "Room"],
            ],
            "migrations": ["new_tag": "v1", "new_sqlite_classes": ["Room"]],
        ]
        let boundary = UUID().uuidString
        var body = Data()
        func addPart(name: String, filename: String?, contentType: String, content: Data) {
            body.append(Data("--\(boundary)\r\n".utf8))
            body.append(Data("Content-Disposition: form-data; name=\"\(name)\";\r\n".utf8))
            if let filename {
                body.append(Data("filename=\"\(filename)\"\r\n".utf8))
            }
            body.append(Data("Content-Type: \(contentType)\r\n\r\n".utf8))
            body.append(content)
            body.append(Data("\r\n".utf8))
        }
        addPart(name: "metadata", filename: nil, contentType: "application/json",
                content: try JSONSerialization.data(withJSONObject: metadata))
        addPart(name: "worker.js", filename: "worker.js", contentType: "application/javascript+module",
                content: Data(scriptContent.utf8))
        body.append(Data("--\(boundary)--\r\n".utf8))

        let url = URL(string: "https://api.cloudflare.com/client/v4/accounts/\(accountID)/workers/scripts/\(Self.scriptName)")!
        var request = URLRequest(url: url)
        request.httpMethod = "PUT"
        request.setValue("Bearer \(oauthToken)", forHTTPHeaderField: "Authorization")
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        let (data, resp) = try await URLSession.shared.data(for: request)
        guard (resp as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              json["success"] as? Bool == true else {
            throw DeployError.apiError(String(decoding: data, as: UTF8.self))
        }
    }

    /// 启用 workers.dev 子域，返回 https://twinperch-relay.<subdomain>.workers.dev
    func enableSubdomain(accountID: String, oauthToken: String) async throws -> URL {
        // 先取账户的 workers.dev 子域
        let subJSON = try await apiGET(
            "https://api.cloudflare.com/client/v4/accounts/\(accountID)/workers/subdomain",
            token: oauthToken)
        guard let subdomain = (subJSON["result"] as? [String: Any])?["subdomain"] as? String else {
            throw DeployError.badResponse
        }
        // 启用脚本的子域访问
        let url = URL(string: "https://api.cloudflare.com/client/v4/accounts/\(accountID)/workers/scripts/\(Self.scriptName)/subdomain")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(oauthToken)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["enabled": true, "previews": false])
        let (data, resp) = try await URLSession.shared.data(for: request)
        guard (resp as? HTTPURLResponse)?.statusCode == 200 else {
            throw DeployError.apiError(String(decoding: data, as: UTF8.self))
        }
        return URL(string: "https://\(Self.scriptName).\(subdomain).workers.dev")!
    }

    private func apiGET(_ urlString: String, token: String) async throws -> [String: Any] {
        var request = URLRequest(url: URL(string: urlString)!)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, resp) = try await URLSession.shared.data(for: request)
        guard (resp as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              json["success"] as? Bool == true else {
            throw DeployError.apiError(String(decoding: data, as: UTF8.self))
        }
        return json
    }
}

/// 部署时上传的 Worker 脚本源（占位结构）。
/// App 打包管线把 Worker/ 的编译产物（esbuild/wrangler 产出的 ESM 单文件）写入此文件，
/// 保持脚本与 Worker/src 同源——不允许出现两份漂移的实现。
public enum TwinPerchRelayScript {
    public static let content = """
    // 由打包管线生成：编译 Worker/src/index.ts（见 Worker/README）。占位以通过编译。
    export default { fetch() { return new Response("placeholder", { status: 500 }); } };
    """
}
