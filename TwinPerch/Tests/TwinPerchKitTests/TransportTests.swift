import XCTest
@testable import TwinPerchKit

/// MIME 构造/解析（传输层只处理自有格式）
final class MIMETests: XCTestCase {

    func testRoundTrip() throws {
        let payload = TP.randomBytes(300)   // 跨多个 base64 行
        let message = TwinMessage(from: "a@qq.com", to: "b@163.com",
                                  transportID: "ABC-123", payload: payload)
        let data = MIME.encode(message)
        let decoded = try MIME.decode(data)
        XCTAssertEqual(decoded.from, "a@qq.com")
        XCTAssertEqual(decoded.to, "b@163.com")
        XCTAssertEqual(decoded.transportID, "ABC-123")
        XCTAssertEqual(decoded.payload, payload)
    }

    func testSubjectContainsNoContent() throws {
        let message = TwinMessage(from: "a@qq.com", to: "b@163.com",
                                  transportID: "X", payload: Data("秘密内容".utf8))
        let text = String(decoding: MIME.encode(message), as: UTF8.self)
        XCTAssertTrue(text.contains("Subject: TwinPerch"))
        // 明文载荷不得出现（base64 编码覆盖）
        XCTAssertFalse(text.contains("秘密内容"))
        // Message-ID 域名固定
        XCTAssertTrue(text.contains("<X@twinperch>"))
    }

    func testTransportIDExtraction() {
        XCTAssertEqual(MIME.transportID(fromMessageID: "<uuid-1@twinperch>"), "uuid-1")
        XCTAssertEqual(MIME.transportID(fromMessageID: "uuid-2@twinperch"), "uuid-2")
    }
}

/// IMAP 客户端（脚本化连接喂真报文）
final class IMAPClientTests: XCTestCase {

    private func makeClient(_ script: [ScriptedMailConnection.ScriptItem]) -> (IMAPClient, ScriptedMailConnection) {
        let conn = ScriptedMailConnection(script)
        return (IMAPClient(connection: conn), conn)
    }

    func testLoginContinuationForm() async throws {
        let (client, conn) = makeClient([
            .line("* OK ready"),
            .line("+ "),
            .line("a1 OK LOGIN completed"),
        ])
        try await client.connect(host: "imap.test", port: 993, tls: true)
        try await client.readGreeting()
        try await client.login(user: "u@qq.com", password: "authcode")
        XCTAssertEqual(conn.sentLines.count, 2)
        XCTAssertEqual(conn.sentLines[0], "a1 AUTHENTICATE PLAIN")
        // SASL 载荷单独一行，含 \0u\0p
        let sasl = conn.sentLines[1]
        XCTAssertEqual(Data(base64Encoded: sasl), Data("\u{0}u@qq.com\u{0}authcode".utf8))
    }

    func testEnsureFolderAcceptsAlreadyExists() async throws {
        let (client, _) = makeClient([
            .line("a1 NO [ALREADYEXISTS] Folder exists"),
        ])
        try await client.ensureFolder("TwinPerch")   // 不应抛错
    }

    func testSearchUnseen() async throws {
        let (client, _) = makeClient([
            .line("* SEARCH 7 9 12"),
            .line("a1 OK SEARCH completed"),
        ])
        let uids = try await client.searchUnseen()
        XCTAssertEqual(uids, [7, 9, 12])
    }

    func testFetchMessageWithLiteral() async throws {
        let mime = MIME.encode(TwinMessage(from: "x@y", to: "z@w",
                                           transportID: "T1", payload: TP.randomBytes(80)))
        let (client, _) = makeClient([
            .line("* 1 FETCH (UID 42 BODY[] {\(mime.count)}"),
            .raw(mime),
            .line(")"),
            .line("a1 OK FETCH completed"),
        ])
        let (uid, data) = try await client.fetchMessage(uid: 42)
        XCTAssertEqual(uid, 42)
        XCTAssertEqual(data, mime)
    }

    func testDeleteAndExpunge() async throws {
        let (client, conn) = makeClient([
            .line("a1 OK STORE completed"),
            .line("a2 OK EXPUNGE completed"),
        ])
        try await client.markDeleted(uid: 7)
        try await client.expunge()
        XCTAssertTrue(conn.sentLines[0].contains("UID STORE 7 +FLAGS.SILENT (\\Deleted)"))
        XCTAssertTrue(conn.sentLines[1].contains("EXPUNGE"))
    }

    func testIdleReceivesExists() async throws {
        let (client, conn) = makeClient([
            .line("+ idling"),
            .line("* 5 EXISTS"),
            .line("a1 OK IDLE terminated"),
        ])
        let got = try await client.idle(timeout: 5)
        XCTAssertTrue(got)
        XCTAssertTrue(conn.sentLines.contains("DONE"))
    }

    func testIdleTimeoutExitsCleanly() async throws {
        let (client, _) = makeClient([
            .line("+ idling"),
            .line("a1 OK IDLE terminated"),
        ])
        // 脚本耗尽/超时都以错误退出（假连接立即耗尽抛 connectionClosed，竞速下二者其一）
        do {
            _ = try await client.idle(timeout: 0.2)
            XCTFail("expected timeout or close")
        } catch let e as IMAPError {
            XCTAssertTrue(e == .timeout || e == .connectionClosed)
        }
    }
}

/// SMTP 客户端
final class SMTPClientTests: XCTestCase {

    func testSendFlow() async throws {
        let mime = MIME.encode(TwinMessage(from: "a@qq.com", to: "b@163.com",
                                           transportID: "T9", payload: TP.randomBytes(50)))
        let conn = ScriptedMailConnection([
            .line("220 smtp.qq.com ESMTP ready"),
            .line("250-smtp.qq.com"),
            .line("250-PIPELINING"),
            .line("250 OK"),                       // EHLO 结束
            .line("235 Authentication successful"), // AUTH
            .line("250 Ok"),                        // MAIL FROM
            .line("250 Ok"),                        // RCPT TO
            .line("354 End data with <CR><LF>.<CR><LF>"),
            .line("250 Ok"),                        // DATA 结束
            .line("221 Bye"),                       // QUIT
        ])
        let client = SMTPClient(connection: conn)
        try await client.send(from: "a@qq.com", to: "b@163.com",
                              authUser: "a@qq.com", authPassword: "code", data: mime)
        let sent = conn.sentLines
        XCTAssertEqual(sent[0], "EHLO twinperch")
        XCTAssertTrue(sent[1].hasPrefix("AUTH PLAIN "))
        XCTAssertEqual(sent[2], "MAIL FROM:<a@qq.com>")
        XCTAssertEqual(sent[3], "RCPT TO:<b@163.com>")
        XCTAssertEqual(sent[4], "DATA")
        // 数据体走 sendRaw：含 MIME、以 .\r\n 结束
        let raw = conn.sentRaw.first!
        XCTAssertTrue(String(decoding: raw, as: UTF8.self).contains("Message-ID: <T9@twinperch>"))
        XCTAssertTrue(String(decoding: raw.suffix(3), as: UTF8.self) == ".\r\n")
    }

    func testDotStuffing() {
        let input = Data("line1\r\n.dotted\r\n.normal\r\n".utf8)
        let out = SMTPClient.dotStuffed(input)
        let text = String(decoding: out, as: UTF8.self)
        XCTAssertTrue(text.contains("..dotted"))
        XCTAssertTrue(text.contains(".normal"))
        XCTAssertTrue(text.hasSuffix(".\r\n"))
    }

    func testDotStuffingNoTrailingCRLF() {
        let input = Data("hello".utf8)   // 无 CRLF
        let out = SMTPClient.dotStuffed(input)
        XCTAssertTrue(String(decoding: out, as: UTF8.self).hasSuffix("hello\r\n.\r\n"))
    }
}

/// CF 帧协议与鉴权 MAC
final class CloudflareTransportTests: XCTestCase {

    func testFrameRoundTripAllCases() {
        let frames: [CFFrame] = [
            .hello(room: "abcd1234abcd1234"),
            .auth(macBase64: "bWFj"),
            .send(id: "u1", envelopeBase64: "ZW52"),
            .ack(ids: ["u1", "u2"]),
            .challenge(nBase64: "Y2hhbGw"),
            .ok(backlog: 5),
            .msg(id: "u3", envelopeBase64: "eHg"),
            .bye(reason: "superseded"),
        ]
        for f in frames {
            let decoded = CFFrame.decode(f.encoded)
            XCTAssertEqual(decoded, f)
        }
        XCTAssertNil(CFFrame.decode(Data("{}".utf8)))
        XCTAssertNil(CFFrame.decode(Data("not json".utf8)))
    }

    func testAuthMacMatchesWorkerAlgorithm() throws {
        // Worker room.ts：HMAC-SHA256(k_room, challenge_bytes) 的 Base64
        let kRoom = TP.randomBytes(32)
        let challenge = TP.randomBytes(32)
        let mac = try XCTUnwrap(CFAuth.mac(authKey: kRoom, challengeBase64: challenge.base64EncodedString()))
        XCTAssertEqual(Data(base64Encoded: mac), TP.hmac(kRoom, challenge))
        XCTAssertNil(CFAuth.mac(authKey: kRoom, challengeBase64: "not-base64!"))
    }

    func testKeyNoticeRoundTrip() throws {
        // 密钥变更通知帧走完整 session 路径
        let (a, b, _, _) = try makePair()
        let notice = try a.makeKeyNotice()
        XCTAssertEqual(notice.kind, .keyNotice)
        let out = try b.receive(notice)
        guard case .message(.keyNotice) = out else {
            return XCTFail("expected keyNotice, got \(out)")
        }
    }
}

/// EmailTransport 集成（脚本化 IMAP/SMTP 连接）
final class EmailTransportTests: XCTestCase {

    private func mimeFor(id: String, payload: Data) -> Data {
        MIME.encode(TwinMessage(from: "b@163.com", to: "a@qq.com",
                                transportID: id, payload: payload))
    }

    func testProvisionFetchAndAck() async throws {
        let m1 = mimeFor(id: "ID-1", payload: TP.randomBytes(40))
        let m2 = mimeFor(id: "ID-2", payload: TP.randomBytes(40))

        let imapConn = ScriptedMailConnection([
            .line("* OK IMAP4rev1 ready"),                    // 问候
            .line("a1 OK LOGIN completed"),                   // AUTHENTICATE
            .line("a2 OK CREATE completed"),                  // CREATE
            .line("a3 OK [READ-WRITE] SELECT completed"),     // SELECT
            .line("* SEARCH 7 9"),                            // UID SEARCH UNSEEN
            .line("a4 OK SEARCH completed"),
            .line("* 1 FETCH (UID 7 BODY[] {\(m1.count)}"),   // FETCH 7
            .raw(m1),
            .line(")"),
            .line("a5 OK FETCH completed"),
            .line("* 2 FETCH (UID 9 BODY[] {\(m2.count)}"),   // FETCH 9
            .raw(m2),
            .line(")"),
            .line("a6 OK FETCH completed"),
            .line("a7 OK STORE completed"),                   // ack: markDeleted(7)
            .line("a8 OK EXPUNGE completed"),                 // ack: expunge
        ])
        let transport = EmailTransport(makeIMAPConnection: { imapConn },
                                       makeSMTPConnection: { ScriptedMailConnection([]) })
        try await transport.provision(.email(EmailAccount(
            address: "a@qq.com", authCode: "code",
            imapHost: "imap.qq.com", imapPort: 993,
            smtpHost: "smtp.qq.com", smtpPort: 465)))

        let received = try await transport.fetchPending()
        XCTAssertEqual(received.map(\.transportID), ["ID-1", "ID-2"])
        XCTAssertEqual(received[0].data.count, 40)

        await transport.ack(transportIDs: ["ID-1"])
        // STORE 只针对已 ack 的 UID 7
        let storeLine = imapConn.sentLines.first { $0.contains("UID STORE") }
        XCTAssertNotNil(storeLine)
        XCTAssertTrue(storeLine!.contains("UID STORE 7"))
        XCTAssertTrue(imapConn.sentLines.contains { $0.contains("EXPUNGE") })
    }

    func testSendUsesSMTP() async throws {
        let imapConn = ScriptedMailConnection([
            .line("* OK ready"),
            .line("a1 OK LOGIN"),
            .line("a2 OK CREATE"),
            .line("a3 OK SELECT"),
        ])
        let smtpConn = ScriptedMailConnection([
            .line("220 ready"),
            .line("250-x"), .line("250 OK"),
            .line("235 ok"),
            .line("250 Ok"), .line("250 Ok"), .line("354 go"),
            .line("250 Ok"), .line("221 bye"),
        ])
        let transport = EmailTransport(makeIMAPConnection: { imapConn },
                                       makeSMTPConnection: { smtpConn })
        try await transport.provision(.email(EmailAccount(
            address: "a@qq.com", authCode: "code",
            imapHost: "imap.qq.com", imapPort: 993,
            smtpHost: "smtp.qq.com", smtpPort: 465)))
        transport.peerAddress = "b@163.com"

        let envelope = TP.randomBytes(64)
        try await transport.send(envelope)
        let raw = try XCTUnwrap(smtpConn.sentRaw.first)
        // 对端地址正确、密文完整
        XCTAssertTrue(smtpConn.sentLines.contains("RCPT TO:<b@163.com>"))
        let text = String(decoding: raw, as: UTF8.self)
        XCTAssertTrue(text.contains("From: a@qq.com"))
        XCTAssertTrue(text.contains("Subject: TwinPerch"))
        // base64 载荷反解回原 envelope
        let decoded = try MIME.decode(raw)
        XCTAssertEqual(decoded.payload, envelope)
    }

    func testProvisionMismatchedCredentialThrows() async throws {
        let transport = EmailTransport()
        do {
            try await transport.provision(.cloudflareRelay(oauthToken: "x"))
            XCTFail("expected throw")
        } catch {
            // 预期：凭证类型不匹配
        }
    }
}
