import SwiftUI
import TwinPerchKit

/// 双栖设计系统（v1）。
///
/// 品牌隐喻：两只鸟共栖一枝（双栖）。视觉基调"安静、私密、有点温度"：
/// - 暮色暖沙（Nest）与黛蓝（Dusk）互为双人色——双方消息各自带一点本方色调，
///   不做 Signal 式蓝灰二分，也不做 Between 式高饱和粉。
/// - 品牌时刻（欢迎页、配对页、安全码）用衬线体；正文 PingFang / SF 为底。
/// 所有视图样式从这里的 token 取，禁止散落硬编码。

public enum DS {

    // MARK: - 色板

    /// 黛蓝（对方 / 冷静 / 夜）
    public static let dusk = Color(red: 0.29, green: 0.36, blue: 0.48)
    /// 暮沙（我方 / 温暖 / 巢）
    public static let nest = Color(red: 0.85, green: 0.66, blue: 0.42)
    /// 品牌主色（按钮、强调）
    public static let accent = dusk
    /// 页面背景
    public static let canvas = Color(red: 0.97, green: 0.96, blue: 0.94)
    /// 卡片 / 气泡底
    public static let surface = Color(red: 1.0, green: 0.99, blue: 0.97)
    /// 我方气泡
    public static let bubbleMine = nest.opacity(0.30)
    /// 对方气泡
    public static let bubbleTheirs = Color(red: 0.90, green: 0.92, blue: 0.95)
    /// 危险 / 失败
    public static let danger = Color(red: 0.78, green: 0.31, blue: 0.28)
    /// 系统提示条
    public static let notice = nest.opacity(0.16)

    // MARK: - 排版

    public static let brandTitle = Font.system(size: 34, weight: .bold, design: .serif)
    public static let brandCaption = Font.system(size: 14, weight: .regular, design: .serif)
    public static let mono = Font.system(.callout, design: .monospaced)
    public static let monoSmall = Font.system(.caption2, design: .monospaced)

    // MARK: - 间距 / 形状

    public static let corner: CGFloat = 14
    public static let bubbleCorner: CGFloat = 16
    public static let spacing: CGFloat = 12

    // MARK: - 组件

    /// 主按钮
    public struct PrimaryButton: View {
        let title: String
        var disabled = false
        let action: () -> Void

        public init(_ title: String, disabled: Bool = false, action: @escaping () -> Void) {
            self.title = title
            self.disabled = disabled
            self.action = action
        }

        public var body: some View {
            Button(action: action) {
                Text(title)
                    .font(.body.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.borderedProminent)
            .tint(DS.accent)
            .disabled(disabled)
        }
    }

    /// 卡片容器
    public struct Card<Content: View>: View {
        let content: Content

        public init(@ViewBuilder content: () -> Content) {
            self.content = content()
        }

        public var body: some View {
            content
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(DS.surface, in: RoundedRectangle(cornerRadius: DS.corner))
                .overlay(
                    RoundedRectangle(cornerRadius: DS.corner)
                        .stroke(Color.black.opacity(0.05), lineWidth: 1)
                )
        }
    }

    /// 系统提示条（会话事件：换钥、解密失败等）
    public struct NoticeBar: View {
        let text: String
        var actionTitle: String?
        var action: (() -> Void)?

        public init(_ text: String, actionTitle: String? = nil, action: (() -> Void)? = nil) {
            self.text = text
            self.actionTitle = actionTitle
            self.action = action
        }

        public var body: some View {
            HStack(spacing: 8) {
                Text(text)
                    .font(.caption)
                    .foregroundStyle(.primary.opacity(0.8))
                if let actionTitle, let action {
                    Button(actionTitle, action: action)
                        .font(.caption.weight(.semibold))
                        .tint(DS.accent)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity)
            .background(DS.notice)
        }
    }

    /// 连接状态横幅
    public struct ConnectionBanner: View {
        let state: ConnectionState

        public init(state: ConnectionState) {
            self.state = state
        }

        public var body: some View {
            switch state {
            case .online:
                EmptyView()
            case .degraded:
                banner("连接不稳定，消息可能延迟", color: .orange)
            case .offline:
                banner("离线：消息已排队，恢复后自动送达", color: .secondary)
            }
        }

        private func banner(_ text: String, color: Color) -> some View {
            Text(text)
                .font(.caption)
                .foregroundStyle(color)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 4)
                .background(color.opacity(0.08))
        }
    }

    // MARK: - 跨平台辅助

    /// 附件 / 媒体底色（跨平台：iOS systemBackground / macOS controlBackgroundColor）
    public static let chrome: Color = {
        #if canImport(UIKit)
        Color(uiColor: .systemBackground)
        #else
        Color(nsColor: .controlBackgroundColor)
        #endif
    }()

    /// 安全码 → 成对色块（签名视觉：两台设备图案一致即互信）
    public static func safetyGlyphs(_ hex: String) -> [Color] {
        let palette: [Color] = [dusk, nest, .teal, .indigo, .orange, .mint, .brown, .purple]
        var out: [Color] = []
        var idx = hex.startIndex
        while idx < hex.endIndex, out.count < 8 {
            let end = hex.index(idx, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            if let byte = UInt8(hex[idx..<end], radix: 16) {
                out.append(palette[Int(byte) % palette.count])
            }
            idx = end
        }
        return out
    }
}
