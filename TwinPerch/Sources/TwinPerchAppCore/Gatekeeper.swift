import Combine
import Foundation
import LocalAuthentication

/// App 门禁状态机（docs/06 §2）：
/// 冷启动锁定；退后台超过阈值（默认 5 分钟）后回前台重新锁定。
/// 评估器可注入：真机用 LAContext（.deviceOwnerAuthentication，Face ID/Touch ID/密码三选一），
/// 测试用假评估器验证状态机本身。

@MainActor
public final class Gatekeeper: ObservableObject {

    public enum LockState: Equatable {
        case locked
        case unlocked
        case authenticating
    }

    @Published public private(set) var state: LockState = .locked
    @Published public private(set) var lastFailure: String?

    public var backgroundThreshold: TimeInterval = 5 * 60
    private var backgroundedAt: Date?

    /// 评估器：返回 true = 通过。默认实现用 LocalAuthentication。
    private let evaluate: @Sendable () async -> Bool

    public init(evaluate: @escaping @Sendable () async -> Bool = { await Gatekeeper.systemEvaluate() }) {
        self.evaluate = evaluate
    }

    /// 系统评估器：LAContext 设备所有者认证（生物识别或密码，系统级安全窗口）
    public nonisolated static func systemEvaluate() async -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            // 设备无锁屏密码：无物可验证，视为通过（与 iOS 惯例一致）
            return true
        }
        return (try? await context.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason: "解锁双栖")) ?? false
    }

    /// App 启动
    public func onLaunch() {
        state = .locked
    }

    /// 退后台
    public func onBackground() {
        backgroundedAt = Date()
    }

    /// 回前台：超过阈值需要验证，否则维持解锁
    public func onForeground() {
        guard state == .unlocked || state == .authenticating else {
            state = .locked
            return
        }
        if let at = backgroundedAt, Date().timeIntervalSince(at) >= backgroundThreshold {
            state = .locked
        } else if state == .authenticating {
            state = .unlocked
        }
        backgroundedAt = nil
    }

    /// 尝试解锁（UI 的解锁按钮 / 自动触发）
    public func authenticate() async {
        guard state == .locked else { return }
        state = .authenticating
        let ok = await evaluate()
        if ok {
            state = .unlocked
            lastFailure = nil
        } else {
            state = .locked
            lastFailure = "验证未通过"
        }
    }

    /// 手动上锁（设置页入口）
    public func lock() {
        state = .locked
    }
}
