import XCTest
@testable import TwinPerchKit

/// URLProtocol 桩：拦截 deployer 的全部请求，记录并回放固定响应
final class MockURLProtocol: URLProtocol {
    nonisolated(unsafe) static var handled: [(method: String, url: String, body: Data?)] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let body = request.httpBody ?? request.httpBodyStream.map { stream -> Data in
            stream.open()
            defer { stream.close() }
            var data = Data()
            let bufSize = 16 * 1024
            let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
            defer { buf.deallocate() }
            while stream.hasBytesAvailable {
                let n = stream.read(buf, maxLength: bufSize)
                if n <= 0 { break }
                data.append(buf, count: n)
            }
            return data
        }
        Self.handled.append((request.httpMethod ?? "GET",
                             request.url?.absoluteString ?? "",
                             body))

        let url = request.url?.absoluteString ?? ""
        let response: HTTPURLResponse
        if url.contains("/bootstrap") {
            // Worker /bootstrap 路由
            response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
        } else if url.contains("/accounts") && url.hasSuffix("/accounts") {
            let json = #"{"success":true,"result":[{"id":"acct123","name":"my"}]}"#
            response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: json.data(using: .utf8)!)
            client?.urlProtocolDidFinishLoading(self)
            return
        } else if url.contains("/workers/subdomain") && !url.contains("/scripts/") {
            let json = #"{"success":true,"result":{"subdomain":"couple.example"}}"#
            response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: json.data(using: .utf8)!)
            client?.urlProtocolDidFinishLoading(self)
            return
        } else if url.contains("/subdomain") && url.contains("/scripts/") {
            let json = #"{"success":true,"result":{"subdomain":"couple.example"}}"#
            response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: json.data(using: .utf8)!)
            client?.urlProtocolDidFinishLoading(self)
            return
        } else {
            // script PUT / subdomain enable POST
            let json = #"{"success":true}"#
            response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: json.data(using: .utf8)!)
            client?.urlProtocolDidFinishLoading(self)
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

final class DeployTests: XCTestCase {

    override func tearDown() {
        MockURLProtocol.handled = []
        super.tearDown()
    }

    /// 生成的 Worker 产物真实存在且包含关键部件
    func testGeneratedRelayScriptIsReal() throws {
        print("DBG generated nil?\(TwinPerchRelayScript.generated == nil) len=\(TwinPerchRelayScript.generated?.count ?? -1) head=\(TwinPerchRelayScript.generated?.prefix(60) ?? "nil")")
        print("DBG has Room: \(TwinPerchRelayScript.generated?.contains("Room") ?? false), bootstrap: \(TwinPerchRelayScript.generated?.contains("bootstrap") ?? false)")
        let content = try TwinPerchRelayScript.requireContent()
        XCTAssertTrue(content.contains("Room"), "产物应包含 DO 类")
        XCTAssertTrue(content.contains("challenge"), "产物应包含鉴权挑战")
        XCTAssertTrue(content.contains("bootstrap"), "产物应包含 /bootstrap 路由")
    }

    /// 完整部署序列：账户 → 脚本（含 DEPLOY_KEY）→ 子域 → bootstrap（含 k_room）
    func testDeploySequence() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        let deployer = CloudflareDeployer(urlSession: URLSession(configuration: config))

        let result = try await deployer.deploy(oauthToken: "tok")
        XCTAssertEqual(result.accountID, "acct123")
        XCTAssertEqual(result.workerURL.absoluteString, "https://twinperch-relay.couple.example.workers.dev")

        // bootstrap：把房间密钥交给 DO
        try await deployer.bootstrapRoom(workerURL: result.workerURL, deployKey: result.deployKey,
                                         roomID: Data(repeating: 1, count: 16),
                                         kRoom: Data(repeating: 2, count: 32),
                                         deviceID: "dev-1")

        let calls = MockURLProtocol.handled
        XCTAssertEqual(calls.count, 5)   // 账户 → 脚本上传 → 子域查询 → 子域启用 → bootstrap
        XCTAssertTrue(calls[0].url.hasSuffix("/accounts"))
        XCTAssertEqual(calls[1].method, "PUT")
        XCTAssertTrue(calls[1].url.contains("/workers/scripts/twinperch-relay"))
        let scriptBody = String(decoding: calls[1].body ?? Data(), as: UTF8.self)
        XCTAssertTrue(scriptBody.contains("DEPLOY_KEY"))
        XCTAssertTrue(scriptBody.contains("name=\"worker.js\""))
        XCTAssertTrue(calls[2].url.contains("/workers/subdomain"))
        XCTAssertTrue(calls[3].url.contains("/scripts/twinperch-relay/subdomain"))
        XCTAssertTrue(calls[4].url.contains("/bootstrap"))
        let bootstrapBody = String(decoding: calls[4].body ?? Data(), as: UTF8.self)
        XCTAssertTrue(bootstrapBody.contains("k_room"))
        XCTAssertTrue(bootstrapBody.contains("dev-1"))
        _ = result.deployKey
    }
}
