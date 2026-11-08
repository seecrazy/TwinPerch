import BackgroundTasks
import Foundation
import TwinPerchAppCore

/// 后台刷新（BGAppRefreshTask）：补发队列 + 拉取积压。
/// ID 必须与 Info.plist 的 BGTaskSchedulerPermittedIdentifiers 一致。
enum BackgroundRefresh {
    static let taskID = "app.twinperch.refresh"

    private static weak var model: AppModel?

    static func register(model: AppModel) {
        self.model = model
        BGTaskScheduler.shared.register(forTaskWithIdentifier: taskID, using: nil) { task in
            run(task: task)
        }
    }

    /// 退后台时提交一次请求（系统择机唤醒）
    static func schedule() {
        let request = BGAppRefreshTaskRequest(identifier: taskID)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 5 * 60)
        try? BGTaskScheduler.shared.submit(request)
    }

    private static func run(task: BGTask) {
        schedule()   // 排下一次
        let work = Task {
            await model?.backgroundFetch()
            task.setTaskCompleted(success: true)
        }
        task.expirationHandler = {
            work.cancel()
        }
    }
}
