import SwiftUI
import UIKit
import TwinPerchAppCore

/// 从最顶层视图控制器全屏弹出扫码页；扫到即关闭并回调。
enum ScannerPresenter {
    static func present() {
        guard let scene = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene }).first,
              let root = scene.windows.first(where: { $0.isKeyWindow })?.rootViewController else { return }
        var top = root
        while let presented = top.presentedViewController { top = presented }

        let hosting = UIHostingController(rootView: ScannerSheet { base64 in
            QRScannerHook.onScanned?(base64)
        })
        hosting.modalPresentationStyle = .fullScreen
        top.present(hosting, animated: true)
    }
}

private struct ScannerSheet: View {
    @Environment(\.dismiss) private var dismiss
    let onScanned: (String) -> Void

    var body: some View {
        ZStack {
            CameraPreview { base64 in
                dismiss()
                onScanned(base64)
            }
            .ignoresSafeArea()

            RoundedRectangle(cornerRadius: DS.bubbleCorner)
                .stroke(DS.surface, lineWidth: 2)
                .frame(width: 260, height: 260)

            VStack {
                HStack {
                    Spacer()
                    Button {
                        dismiss()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.title)
                            .foregroundStyle(.white)
                    }
                    .padding(16)
                }
                Spacer()
                Text("对准对方的二维码")
                    .font(.callout)
                    .foregroundStyle(.white)
                    .padding(.bottom, 60)
            }
        }
    }
}
