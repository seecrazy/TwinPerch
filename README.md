# 双栖 TwinPerch

面向情侣的端到端加密私密通信 App。核心理念：**每对情侣拥有自己的加密信箱，
开发者不运营消息通道、不接触数据。**

设计文档见 [docs/](docs/)（7 份：总体架构、加密协议、传输抽象、邮箱传输、
Cloudflare 传输、推送代理、客户端与路线图）。

## 仓库结构

```
docs/                 设计文档 v2（00-06 架构与协议，07 UI 设计，08 进度账本）
ios/                  iOS 工程壳：TwinPerchApp（扫码/BGTask/APNs/生命周期）+ Info.plist + entitlements
TwinPerch.xcodeproj   手写现代格式工程（文件系统同步组 + 本地 SPM 依赖）
TwinPerch/            Swift Package（零第三方依赖）
  Sources/TwinPerchKit/
    Crypto/           TP-Crypt v1：握手 / 链棘轮 / Envelope / 最小 CBOR（纯 CryptoKit）
    Session/          会话状态机：回执捎带、去重、重同步、密钥变更通知、持久化
    Vault/            本地加密库：SQLite3 + 列级 AES-GCM + excludedFromBackup
    Transport/        RelayTransport 抽象 + 邮箱传输（IMAP/SMTP/MIME）+ CF WS 客户端 + 部署 API
    Push/             推送代理客户端（opt-in）
  Sources/TwinPerchAppCore/   AppModel 状态机 + DS 设计系统 + SwiftUI 视图（iOS/macOS 双编译）
                              发件队列 / 附件分块 / 门禁 / 设置页 / 授权码引导 / 分页历史 / 部署编排
  Sources/TwinPerchAppDemo/   macOS 演示入口（验证 App 层可编译运行）
  Tests/              48 项单元测试 + Python 交叉验证向量
tools/pyref/          Python 参考实现（零依赖）+ 测试向量生成器
Worker/               twinperch-relay：每对情侣自部署的 Cloudflare Worker + DO（Hibernation）
PushProxy/            推送代理（开发者运营的唯一组件，opt-in、内容零知识）
```

## 构建与测试

```bash
# Swift 全量测试（加密核心 + 会话 + Vault + 向量交叉验证）
cd TwinPerch && swift test

# Python 参考实现自检 + 重新生成向量（向量为确定性输入，可复现）
python3 tools/pyref/tpcrypt_ref.py
python3 tools/pyref/gen_vectors.py

# Worker / PushProxy 类型检查 + Worker 打包管线（消除部署占位符）
cd Worker    && npm install && npx tsc --noEmit && npm run bundle
cd PushProxy && npm install && npx tsc --noEmit

# iOS App：构建到模拟器并运行
xcodebuild -project TwinPerch.xcodeproj -scheme TwinPerch \
  -destination 'platform=iOS Simulator,name=iPhone 18 Pro' CODE_SIGNING_ALLOWED=NO build
xcrun simctl install booted <产物路径>/TwinPerch.app && xcrun simctl launch booted app.twinperch
```

当前测试基线：**58/58 通过**（含部署全序列 MockURLProtocol 测试与生成产物校验）。
覆盖：加密双实现对拍、发件队列、附件分块、重同步、门禁、分页、重配对、部署序列。向量测试将 Swift 与 Python 两个独立实现对拍：
握手派生物逐项一致、502 条消息的完整 envelope 逐字节一致、乱序消费一致。
邮箱传输的 IMAP/SMTP/MIME 协议逻辑以脚本化连接喂真实报文覆盖；CF WS 帧编解码
与鉴权 MAC 与 Worker 实现对齐；App 编排层（双端配对→收发→回执→密钥变更提示）
有端到端测试。

## iOS 工程壳（待生成）

AppCore 的 RootView + AppModel 是 iOS/macOS 双编译的；正式 iOS App 在 Xcode 里
新建项目后挂载这两个 target 即可，壳层需补（均为平台能力，非业务逻辑）：
门禁（LocalAuthentication，冷启动 + 后台超 5 分钟）、相机扫码（AVFoundation 替换
粘贴框）、BGTaskScheduler 后台补账、APNs 注册（opt-in 推送）、
`.completeFileProtection` 与 excludedFromBackup 的 Info.plist/ entitlement 配置。

## 进度账本

详见 [docs/08-进度.md](docs/08-进度.md)（时间线、验证清单、已知边界）。

## 人工验证待办（Phase 0 余项，已按约定全部后置）

- [ ] Cloudflare 免费账户：OAuth → API 部署 Worker/DO → /bootstrap 全流程实连
- [ ] QQ 邮箱 IMAP IDLE 在 iOS 真机上的后台存活与延迟实测（TLSMailConnection 实连）
- [ ] 加密协议外审（docs/01 + 实现一起看）
- [ ] 首发市场定稿（大陆 → 邮箱主干；纯海外 → 邮箱 + CF 双选）

## 状态

- ✅ 加密协议实现与双实现交叉验证（Phase 0 第 1 项）
- ✅ 邮箱传输（IMAP/SMTP 子集 + MIME + IDLE 轮询编排）
- ✅ Cloudflare WS 客户端 + API 部署流（CloudflareDeployer）+ /bootstrap
- ✅ 推送代理客户端 + 密钥变更通知 + AppModel + SwiftUI 视图
- ⏳ 人工验证清单（上表）+ iOS Xcode 工程壳
- 设计决策与待办详见 docs/06-客户端与路线图.md
