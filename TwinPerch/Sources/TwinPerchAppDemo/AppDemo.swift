import SwiftUI
import TwinPerchAppCore
import TwinPerchKit

/// macOS 演示入口：验证 AppCore（AppModel + 视图）可编译可运行。
/// iOS 工程壳（Xcode 项目）挂载同一 RootView + AppModel，并叠加：
/// - 门禁（LocalAuthentication，冷启动 + 后台超 5 分钟）
/// - 相机扫码（AVFoundation）替换粘贴框
/// - BGTaskScheduler 后台补账
/// - APNs 注册（opt-in 推送）
@main
struct TwinPerchDemoApp: App {
    @StateObject private var model = AppModel(keyStore: KeychainKeyStore())
    @StateObject private var gate = Gatekeeper()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .environmentObject(gate)
                .frame(minWidth: 420, minHeight: 560)
                .onAppear { gate.onLaunch() }
        }
        .onChange(of: NotificationCenter.default) { _ in }
    }
}
