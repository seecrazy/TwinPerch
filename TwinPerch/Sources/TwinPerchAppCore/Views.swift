import CoreImage
import SwiftUI
import TwinPerchKit

/// 根视图：门禁 → 按 Phase 切换 欢迎页 / 配对页 / 聊天页。
/// iOS 工程壳在本视图外补：相机扫码、BGTask、APNs 注册、entitlements。
public struct RootView: View {
    @EnvironmentObject public var model: AppModel
    @EnvironmentObject public var gate: Gatekeeper

    public init() {}

    public var body: some View {
        ZStack {
            DS.canvas.ignoresSafeArea()
            switch gate.state {
            case .locked, .authenticating:
                LockView()
            case .unlocked:
                content
            }
        }
    }

    @ViewBuilder
    private var content: some View {
        switch model.phase {
        case .fresh:
            WelcomeView()
        case .pairingShowMyQR(let qr):
            PairingView(qrBase64: qr)
        case .active:
            ChatView()
        }
    }
}

// MARK: - 门禁页

public struct LockView: View {
    @EnvironmentObject private var gate: Gatekeeper

    public init() {}

    public var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "bird.fill")
                .font(.system(size: 52))
                .foregroundStyle(DS.dusk)
                .padding(.bottom, 4)
            Text("双栖")
                .font(DS.brandTitle)
                .foregroundStyle(DS.dusk)
            Text("只有你们能进的领地")
                .font(DS.brandCaption)
                .foregroundStyle(.secondary)
            DS.PrimaryButton("解锁") {
                Task { await gate.authenticate() }
            }
            .frame(maxWidth: 240)
            if let failure = gate.lastFailure {
                Text(failure).font(.caption).foregroundStyle(DS.danger)
            }
        }
        .padding(40)
        .task { await gate.authenticate() }
    }
}

// MARK: - 欢迎页

public struct WelcomeView: View {
    @EnvironmentObject private var model: AppModel
    @State private var address: String = ""
    @State private var showResponderSheet = false

    public init() {}

    public var body: some View {
        ScrollView {
            VStack(spacing: DS.spacing * 2) {
                VStack(spacing: 6) {
                    Text("双栖")
                        .font(DS.brandTitle)
                        .foregroundStyle(DS.dusk)
                    Text("两个人各自独立，共享一片只有彼此能进的领地")
                        .font(DS.brandCaption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding(.top, 24)

                DS.Card {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("先确认你的邮箱").font(.headline)
                        TextField("你的邮箱（QQ / 163 等，可留空）", text: $address)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                        Text("配对不联网：二维码只在你们之间传递。邮箱仅用于建立加密信箱。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                DS.PrimaryButton("我是发起方，出码") {
                    _ = try? model.beginPairing(address: address.isEmpty ? nil : address, isInitiator: true)
                }

                Button("我已扫到对方的码（响应方）") {
                    showResponderSheet = true
                }
                .font(.subheadline)

                if let err = model.lastError {
                    Text(err).font(.caption).foregroundStyle(DS.danger)
                }
            }
            .padding(24)
        }
        .sheet(isPresented: $showResponderSheet) {
            ResponderSheet(address: address)
        }
    }
}

/// 响应方入口：粘贴（真机换扫码）对方码 → 出自己的码
public struct ResponderSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let address: String
    @State private var peerQR: String = ""
    @State private var myQR: String?

    public init(address: String) {
        self.address = address
    }

    public var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                if let myQR {
                    Text("把这枚码给对方扫").font(.headline)
                    QRCodeImage(base64: myQR)
                        .frame(width: 200, height: 200)
                    DS.PrimaryButton("完成") {
                        model.finishResponderPairing()
                        dismiss()
                    }
                } else {
                    if QRScannerHook.canScan {
                        DS.PrimaryButton("扫描对方的码") {
                            QRScannerHook.present?()
                        }
                    }
                    Text("或粘贴对方二维码的内容")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextField("对方二维码 Base64", text: $peerQR)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                    DS.PrimaryButton("接受配对") {
                        myQR = try? model.acceptAsResponder(peerQRBase64: peerQR, address: address.isEmpty ? nil : address)
                    }
                    .disabled(peerQR.isEmpty)
                }
            }
            .padding(24)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
            }
        }
    }
}

// MARK: - 配对页（仪式感：出码 → 对方扫 → 安全校比对 → 完成进入）

public struct PairingView: View {
    @EnvironmentObject private var model: AppModel
    let qrBase64: String
    @State private var pastedPeerQR: String = ""

    public init(qrBase64: String) {
        self.qrBase64 = qrBase64
    }

    public var body: some View {
        ScrollView {
            VStack(spacing: DS.spacing * 2) {
                VStack(spacing: 6) {
                    Text("面对面配对")
                        .font(.title2.bold())
                    Text("两人当面完成。二维码不经过任何服务器。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, 20)

                DS.Card {
                    VStack(spacing: 12) {
                        QRCodeImage(base64: qrBase64)
                            .frame(width: 210, height: 210)
                        Text(qrBase64.isEmpty ? "请先扫对方的码" : "让 ta 扫这枚码")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                }

                if !model.safetyCodeHex.isEmpty {
                    SafetyCodeCard(code: model.safetyCodeHex)
                }

                if !model.safetyCodeHex.isEmpty {
                    // 握手已过半：发起方贴对方码收尾；响应方直接完成
                    if model.peerAddress != nil || model.session != nil {
                        DS.PrimaryButton("进入双栖") {
                            if model.session != nil {
                                model.finishResponderPairing()
                            }
                        }
                    }
                    if QRScannerHook.canScan {
                        DS.PrimaryButton("扫描对方的码，完成配对") {
                            QRScannerHook.present?()
                        }
                    }
                    TextField("或粘贴对方二维码 Base64", text: $pastedPeerQR)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                    DS.PrimaryButton("完成配对") {
                        try? model.completeAsInitiator(peerQRBase64: pastedPeerQR)
                    }
                    .disabled(pastedPeerQR.isEmpty)
                }
            }
            .padding(24)
        }
    }
}

/// 安全码卡片：8 枚成对色块 + hex 备查。两台设备图案一致 = 互信。
public struct SafetyCodeCard: View {
    let code: String

    public init(code: String) {
        self.code = code
    }

    public var body: some View {
        DS.Card {
            VStack(spacing: 10) {
                Text("安全码 · 两台设备必须一致")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack(spacing: 10) {
                    ForEach(Array(DS.safetyGlyphs(code).enumerated()), id: \.offset) { _, color in
                        RoundedRectangle(cornerRadius: 6)
                            .fill(color)
                            .frame(width: 26, height: 26)
                    }
                }
                Text(code.grouped(4))
                    .font(DS.monoSmall)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity)
        }
    }
}

// MARK: - 聊天页

public struct ChatView: View {
    @EnvironmentObject private var model: AppModel
    @State private var draft: String = ""
    @State private var showSettings = false
    @State private var showAttachmentPicker = false

    public init() {}

    public var body: some View {
        VStack(spacing: 0) {
            header
            DS.ConnectionBanner(state: model.connectionState)
            if model.needsResyncHint {
                DS.NoticeBar("有消息无法解密，可能需要重新同步", actionTitle: "请求重同步") {
                    try? model.sendSyncRequest()
                }
            }
            messageList
            inputBar
        }
        .background(DS.canvas)
        .sheet(isPresented: $showSettings) {
            NavigationStack { SettingsView() }
        }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(model.peerAddress ?? "TA")
                    .font(.headline)
                HStack(spacing: 6) {
                    if let label = model.transportLabel {
                        Text(label).font(.caption2).foregroundStyle(.secondary)
                    } else {
                        Text("未连接").font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
            Spacer()
            Button {
                showSettings = true
            } label: {
                Image(systemName: "gearshape")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 6) {
                    if model.canLoadOlder {
                        Button("加载更早的消息") {
                            model.loadOlderMessages()
                        }
                        .font(.caption)
                        .padding(.vertical, 6)
                    }
                    ForEach(Array(model.messages.enumerated()), id: \.element.id) { index, msg in
                        if isDayBoundary(index: index) {
                            DaySeparator(date: msg.timestamp)
                        }
                        MessageBubble(message: msg)
                            .id(msg.id)
                    }
                }
                .padding(12)
            }
            .onChange(of: model.messages.count) { _ in
                if let last = model.messages.last {
                    proxy.scrollTo(last.id, anchor: .bottom)
                    if !last.isOutgoing {
                        try? model.markAllRead()
                    }
                }
            }
        }
    }

    private func isDayBoundary(index: Int) -> Bool {
        guard index > 0 else { return true }
        return day(of: model.messages[index - 1].timestamp) != day(of: model.messages[index].timestamp)
    }

    private func day(of ts: UInt64) -> String {
        Self.dayFormatter.string(from: Date(timeIntervalSince1970: Double(ts) / 1000))
    }

    static let dayFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "M月d日 EEEE"
        f.locale = Locale(identifier: "zh_CN")
        return f
    }()

    private var inputBar: some View {
        HStack(spacing: 8) {
            Button {
                showAttachmentPicker = true
            } label: {
                Image(systemName: "photo")
            }
            .buttonStyle(.borderless)
            TextField("说点什么…", text: $draft, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .lineLimit(1...4)
                .onSubmit(send)
            Button(action: send) {
                Image(systemName: "paperplane.fill")
            }
            .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty || model.session == nil)
            .buttonStyle(.borderedProminent)
            .tint(DS.accent)
        }
        .padding(12)
        .background(.bar)
        .sheet(isPresented: $showAttachmentPicker) {
            AttachmentPickerSheet()
        }
    }

    private func send() {
        let text = draft.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }
        try? model.sendText(text)
        draft = ""
    }
}

/// 附件选择（macOS 文件选板；真机换 PhotosPicker / fileImporter）
public struct AttachmentPickerSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var path: String = ""
    @State private var name: String = ""

    public init() {}

    public var body: some View {
        VStack(spacing: 14) {
            Text("发送附件（加密传输，≤ 20MB）")
                .font(.headline)
            TextField("文件路径（真机为系统选择器）", text: $path)
                .textFieldStyle(.roundedBorder)
            TextField("显示名", text: $name)
                .textFieldStyle(.roundedBorder)
            DS.PrimaryButton("加密并发送") {
                let url = URL(fileURLWithPath: path)
                let mime = url.pathExtension.lowercased() == "png" ? "image/png" : "application/octet-stream"
                try? model.sendAttachment(fileURL: url, name: name.isEmpty ? url.lastPathComponent : name, mime: mime)
                dismiss()
            }
            .disabled(path.isEmpty)
        }
        .padding(24)
    }
}

public struct MessageBubble: View {
    @EnvironmentObject private var model: AppModel
    let message: AppModel.ChatMessage

    public init(message: AppModel.ChatMessage) {
        self.message = message
    }

    public var body: some View {
        HStack {
            if message.isOutgoing { Spacer(minLength: 56) }
            VStack(alignment: message.isOutgoing ? .trailing : .leading, spacing: 3) {
                bubble
                HStack(spacing: 4) {
                    Text(Self.timeFormatter.string(from: Date(timeIntervalSince1970: Double(message.timestamp) / 1000)))
                    if message.isOutgoing {
                        sendStateMark
                    }
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
            }
            if !message.isOutgoing { Spacer(minLength: 56) }
        }
        .padding(.horizontal, 4)
    }

    @ViewBuilder
    private var bubble: some View {
        let shape = RoundedRectangle(cornerRadius: DS.bubbleCorner)
        if let att = message.attachment {
            attachmentContent(att)
                .frame(maxWidth: 220)
                .padding(6)
                .background(message.isOutgoing ? DS.bubbleMine : DS.bubbleTheirs, in: shape)
        } else {
            Text(message.text)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(message.isOutgoing ? DS.bubbleMine : DS.bubbleTheirs, in: shape)
        }
    }

    @ViewBuilder
    private func attachmentContent(_ att: AppModel.AttachmentRef) -> some View {
        if att.isImage {
            if let image = AttachmentThumbLoader.thumbnail(model: model, ref: att) {
                image
                    .resizable()
                    .scaledToFit()
                    .clipShape(RoundedRectangle(cornerRadius: DS.bubbleCorner - 6))
            } else {
                Label(att.name, systemImage: "photo")
                    .font(.caption)
            }
        } else {
            Label("\(att.name)（\(metaSize(att))）", systemImage: "doc")
                .font(.caption)
        }
    }

    private func metaSize(_ att: AppModel.AttachmentRef) -> String {
        guard let (_, data) = try? model.attachment(id: att.fileID) else { return "" }
        return ByteCountFormatter.string(fromByteCount: Int64(data.count), countStyle: .file)
    }

    @ViewBuilder
    private var sendStateMark: some View {
        switch message.sendState {
        case .sending:
            Image(systemName: "clock")
        case .sent:
            if message.read {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(DS.dusk)
            } else {
                Image(systemName: "checkmark")
            }
        case .failed:
            Image(systemName: "exclamationmark.circle.fill").foregroundStyle(DS.danger)
        }
    }

    static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm"
        return f
    }()
}

/// 日期分隔条
public struct DaySeparator: View {
    let date: UInt64

    public init(date: UInt64) {
        self.date = date
    }

    public var body: some View {
        Text(ChatView.dayFormatter.string(from: Date(timeIntervalSince1970: Double(date) / 1000)))
            .font(.caption2)
            .foregroundStyle(.secondary)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity)
    }
}

// MARK: - 附件缩略图（跨平台；从 Vault 解密读回）

enum AttachmentThumbLoader {
    /// 附件解密 → 平台图片。真机大图应落盘后按需加载（v1 内存直读，附件 ≤ 20MB）。
    @MainActor
    static func thumbnail(model: AppModel, ref: AppModel.AttachmentRef) -> Image? {
        guard let (_, data) = try? model.attachment(id: ref.fileID) else { return nil }
        #if canImport(UIKit)
        if let ui = UIImage(data: data) { return Image(uiImage: ui) }
        return nil
        #elseif canImport(AppKit)
        if let ns = NSImage(data: data) { return Image(nsImage: ns) }
        return nil
        #endif
    }
}

// MARK: - 设置页

public struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var showResetConfirm = false

    public init() {}

    public var body: some View {
        Form {
            Section("加密与身份") {
                if !model.safetyCodeHex.isEmpty {
                    SafetyCodeCard(code: model.safetyCodeHex)
                }
                Button("重新配对（更换密钥）", role: .destructive) {
                    showResetConfirm = true
                }
            }

            Section("连接方式") {
                NavigationLink("邮箱信箱（推荐）") {
                    EmailSetupView()
                }
                NavigationLink("自托管中转") {
                    ManualRelayView()
                }
                if let label = model.transportLabel {
                    HStack {
                        Text("当前").foregroundStyle(.secondary)
                        Spacer()
                        Text(label).font(.caption)
                    }
                    Button("断开", role: .destructive) {
                        Task { await model.disconnectTransport() }
                    }
                }
            }

            Section("通知") {
                PushToggle()
                Text("开启后，通知服务只会收到一个随机设备编号和新消息条数；内容与身份仍然只有你们可见。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("关于") {
                LabeledContent("消息", value: "端到端加密，服务商只见密文")
                LabeledContent("存储", value: "仅本机，已排除 iCloud 备份")
                LabeledContent("元数据", value: "时间与地址对服务商可见")
                LabeledContent("丢机", value: "密钥不外传，历史将不可恢复")
            }
        }
        .navigationTitle("设置")
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("完成") { dismiss() }
            }
        }
        .confirmationDialog("重新配对会作废当前密钥，对方会收到变更通知。继续？",
                            isPresented: $showResetConfirm, titleVisibility: .visible) {
            Button("重新配对", role: .destructive) {
                model.resetPairing()
                dismiss()
            }
        }
    }
}

/// 邮箱接入 + 分服务商授权码引导（docs/03 §1：本方案唯一门槛）
public struct EmailSetupView: View {
    @EnvironmentObject private var model: AppModel
    @State private var providerIndex = 0
    @State private var address: String = ""
    @State private var authCode: String = ""
    @State private var peerAddress: String = ""
    @State private var status: String?

    public init() {}

    private var preset: MailProviderPreset { MailProviderPreset.presets[providerIndex] }

    public var body: some View {
        Form {
            Section("选择服务商") {
                Picker("服务商", selection: $providerIndex) {
                    ForEach(Array(MailProviderPreset.presets.enumerated()), id: \.offset) { i, p in
                        Text(p.name).tag(i)
                    }
                }
            }

            Section("开启 IMAP 并生成授权码（\(preset.name)）") {
                guide
            }

            Section("登录") {
                TextField("邮箱地址", text: $address)
                    .autocorrectionDisabled()
                SecureField(preset.usesAuthCode ? "授权码（不是登录密码）" : "应用专用密码", text: $authCode)
                TextField("对方的邮箱地址", text: $peerAddress)
                    .autocorrectionDisabled()
            }

            Section {
                DS.PrimaryButton("连接") {
                    let account = EmailAccount(address: address, authCode: authCode,
                                               imapHost: preset.imapHost, imapPort: preset.imapPort,
                                               smtpHost: preset.smtpHost, smtpPort: preset.smtpPort)
                    Task {
                        do {
                            try await model.connectEmail(account: account,
                                                         peerAddress: peerAddress.isEmpty ? nil : peerAddress)
                            await MainActor.run { status = "已连接" }
                        } catch {
                            await MainActor.run { status = "连接失败：\(error)" }
                        }
                    }
                }
                if let status {
                    Text(status).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("邮箱信箱")
    }

    @ViewBuilder
    private var guide: some View {
        let steps = providerGuide(preset)
        ForEach(Array(steps.enumerated()), id: \.offset) { i, step in
            HStack(alignment: .top, spacing: 10) {
                Text("\(i + 1)")
                    .font(.caption.weight(.bold))
                    .frame(width: 18, height: 18)
                    .background(DS.accent.opacity(0.15), in: Circle())
                Text(step).font(.subheadline)
            }
        }
    }

    private func providerGuide(_ p: MailProviderPreset) -> [String] {
        switch p.name {
        case "QQ 邮箱":
            return ["网页登录 mail.qq.com → 设置 → 账户",
                    "找到「POP3/IMAP/SMTP」服务，开启「IMAP/SMTP 服务」",
                    "按提示短信验证后生成「授权码」（16 位字母）",
                    "在下方使用邮箱地址 + 授权码登录（不是 QQ 密码）"]
        case "163 邮箱", "126 邮箱":
            return ["网页登录邮箱 → 设置 → POP3/SMTP/IMAP",
                    "开启「IMAP/SMTP 服务」",
                    "新增「授权密码」（与服务区密码不同）",
                    "在下方使用邮箱地址 + 授权密码登录"]
        default:
            return ["在服务商设置中开启 IMAP 访问",
                    p.usesAuthCode ? "生成应用专用密码后填入下方" : "按服务商指引生成应用专用密码",
                    "在下方登录"]
        }
    }
}

/// 自托管中转（便携 relay 二进制 / VPS）
public struct ManualRelayView: View {
    @EnvironmentObject private var model: AppModel
    @State private var urlText: String = ""
    @State private var status: String?

    public init() {}

    public var body: some View {
        Form {
            Section("中转地址") {
                TextField("https://your-relay.example.com", text: $urlText)
                    .autocorrectionDisabled()
                Text("自托管便携中转（第三阶段交付）或自部署的 Cloudflare Worker 地址。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section {
                DS.PrimaryButton("连接") {
                    guard let url = URL(string: urlText), url.scheme != nil else {
                        status = "地址无效"
                        return
                    }
                    Task {
                        do {
                            try await model.connectManualRelay(url: url)
                            await MainActor.run { status = "已连接" }
                        } catch {
                            await MainActor.run { status = "连接失败：\(error)" }
                        }
                    }
                }
                if let status { Text(status).font(.caption).foregroundStyle(.secondary) }
            }
        }
        .navigationTitle("自托管中转")
    }
}

/// 推送 opt-in 开关
public struct PushToggle: View {
    @EnvironmentObject private var model: AppModel
    @AppStorage("tp.push.enabled") private var enabled = false
    @State private var proxyURLText: String = "https://push.twinperch.app"

    public init() {}

    public var body: some View {
        Toggle("即时提醒", isOn: $enabled)
            .onChange(of: enabled) { newValue in
                guard let url = URL(string: proxyURLText) else { return }
                Task { await model.setPushEnabled(newValue, proxyURL: url) }
            }
    }
}

// MARK: - QR 渲染（双平台）

public struct QRCodeImage: View {
    let base64: String

    public init(base64: String) {
        self.base64 = base64
    }

    public var body: some View {
        Group {
            if let image = QRCodeRenderer.image(fromBase64: base64) {
                image
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
            } else {
                RoundedRectangle(cornerRadius: DS.corner)
                    .fill(DS.surface)
                    .overlay(Text("二维码内容为空").font(.caption).foregroundStyle(.secondary))
            }
        }
        .padding(10)
        .background(.white, in: RoundedRectangle(cornerRadius: DS.corner))
    }
}

public enum QRCodeRenderer {
    public static func image(fromBase64 base64: String) -> Image? {
        guard let data = Data(base64Encoded: base64), !data.isEmpty else { return nil }
        let filter = CIFilter(name: "CIQRCodeGenerator")
        filter?.setValue(data, forKey: "inputMessage")
        guard let scaled = filter?.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)) else {
            return nil
        }
        #if canImport(UIKit)
        if let cg = CIContext().createCGImage(scaled, from: scaled.extent) {
            return Image(uiImage: UIImage(cgImage: cg))
        }
        return nil
        #elseif canImport(AppKit)
        let rep = NSCIImageRep(ciImage: scaled)
        let nsImage = NSImage(size: rep.size)
        nsImage.addRepresentation(rep)
        return Image(nsImage: nsImage)
        #else
        return nil
        #endif
    }
}

// MARK: - 小工具

extension String {
    func grouped(_ size: Int) -> String {
        var out: [String] = []
        var idx = startIndex
        while idx < endIndex {
            let end = index(idx, offsetBy: size, limitedBy: endIndex) ?? endIndex
            out.append(String(self[idx..<end]))
            idx = end
        }
        return out.joined(separator: " ")
    }
}
