import UIKit
import UserNotifications
import TwinPerchAppCore

/// 推送接线（docs/05）：通知权限 + APNs 注册。
/// opt-in 的开关逻辑在 AppModel.setPushEnabled；这里只负责拿到 token。
enum PushSetup {
    static func registerForRemoteNotifications() {
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
            // 权限拒绝不影响应用内收发；推送注册仍可进行（通知不展示）
            if granted {
                center.delegate = NotificationCenterDelegate.shared
            }
            DispatchQueue.main.async {
                UIApplication.shared.registerForRemoteNotifications()
            }
        }
    }
}

/// 固定文案的通知展示（推送 payload 不含内容，见 docs/05 §3）
final class NotificationCenterDelegate: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NotificationCenterDelegate()

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }
}
