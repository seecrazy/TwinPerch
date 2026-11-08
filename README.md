# 双栖 TwinPerch

面向情侣的端到端加密私密通信 App。核心理念：**每对情侣拥有自己的加密信箱，
开发者不运营消息通道、不接触数据。**

设计文档见 [docs/](docs/)（7 份：总体架构、加密协议、传输抽象、邮箱传输、
Cloudflare 传输、推送代理、客户端与路线图）。

## 仓库结构

```
docs/                 设计文档 v2（2026-11-08）
TwinPerch/            Swift Package（零第三方依赖）
  Sources/TwinPerchKit/
    Crypto/           TP-Crypt v1：握手 / 链棘轮 / Envelope / 最小 CBOR（纯 CryptoKit）
    Session/          会话状态机：回执捎带、去重、重同步、密钥变更通知、持久化
    Vault/            本地加密库：SQLite3 + 列级 AES-GCM + excludedFromBackup
    Transport/        RelayTransport 抽象 + 邮箱传输（IMAP/SMTP/MIME）+ CF WS 客户端 + 部署 API
    Push/             推送代理客户端（opt-in）
  Sources/TwinPerchAppCore/   AppModel 状态机 + 设计系统 + SwiftUI 视图（iOS/macOS 双编译）
                              发件队列 / 附件分块 / 门禁 / 设置页 / 授权码引导 / 分页历史
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

# Worker / PushProxy 类型检查
cd Worker    && npm install && npx tsc --noEmit
cd PushProxy && npm install && npx tsc --noEmit
```

当前测试基线：**56/56 通过**。新增覆盖：发件队列（失败不丢消息、重试、上线自动补发）、
附件分块协议（多块往返逐字节一致）、解密失败提示与一键重同步、门禁状态机、历史分页、重配对。向量测试将 Swift 与 Python 两个独立实现对拍：
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
