import SwiftUI
import TwinPerchAppCore
import TwinPerchKit

/// iOS App 入口：挂载共享 RootView + AppModel + Gatekeeper，
/// 并接线平台能力（生命周期门禁、相机扫码、推送注册、后台刷新）。
@main
struct TwinPerchApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel(keyStore: KeychainKeyStore())
    @StateObject private var gate = Gatekeeper()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .environmentObject(gate)
                .tint(DS.accent)
                .onAppear {
                    AppDelegate.model = model
                    gate.onLaunch()
                    BackgroundRefresh.register(model: model)
                    wireScanner(model: model)
                }
        }
        .onChange(of: scenePhase) { phase in
            switch phase {
            case .background:
                gate.onBackground()
                BackgroundRefresh.schedule()
            case .active:
                gate.onForeground()
            default:
                break
            }
        }
    }

    /// 相机扫码接线：设置页/配对页的"扫码"按钮 → 系统相机 → 配对状态机分派
    private func wireScanner(model: AppModel) {
        QRScannerHook.canScan = true
        QRScannerHook.onScanned = { base64 in
            Task { @MainActor in
                try? model.ingestPeerQR(base64)
            }
        }
        QRScannerHook.present = {
            ScannerPresenter.present()
        }
    }
}

/// APNs token 回调经 AppDelegate 进入共享模型
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    static weak var model: AppModel?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        PushSetup.registerForRemoteNotifications()
        return true
    }

    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Task { @MainActor in
            await Self.model?.updateAPNsToken(deviceToken)
        }
    }

    /// 推送 payload 不含内容（docs/05），前台也照常展示固定文案
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }
}
