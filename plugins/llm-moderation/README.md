# `@loomward/plugin-llm-moderation` — 多模态 LLM 内容审查插件

面向 LoomWard · 织盾的进程外（`executionBoundary: "out-of-process"`）多模态内容安全审查插件，挂载顺序严格位于离线 `antileak` 护栏（`order: 10`）之后（`order: 50`），兼容三大核心审查模式与原生端到端流式校验。

## 能力总览

- **三大审查模式**：
  - `local-only`：本地 Guard 模型（原生 Ollama `/api/chat` + `/api/tags` / `/api/ps` 模型发现与管理、vLLM / llama.cpp / ModelBridge OpenAI 兼容端点，或内置确定性本地规则评估）；对 `qwen3` 等推理模型默认下发 `think: false` 并剥离 `<think>` 块，仅对通用分类模型启用 `format: "json"`（对 `llama-guard` / `shieldgemma` 保持原生安全标签输出），并支持向原生 Ollama 直接传递多模态图像 `images` 字段。
  - `guard-plus-canary`：Guard 模型 + 小模型**防诱导金丝雀探针（Zero-Tool Prompt Inducement Canary Probe）**，以及灰区 `[grayZoneLow, grayZoneHigh]` 级联复核与异步 Shadow A/B 遥测；另附离线 JSONL 基准评测器 `engine/eval_runner.py`。
  - `cloud-first` / `hybrid-tiered`：接入 OpenAI Moderation Compat / 通用 Webhook、阿里云内容安全 2.0（Green-CIP）、腾讯云天御（TMS / IMS / AMS 同步音频 / VMS）、百度智能云 AIP 内容审核，受统一安全控制台（默认 `18797`）侧边栏「LLM 审查策略」全局 `cloudOptIn` 开关门控；页面内直接提供厂商服务地域（`cloudRegion`）选择与只写 API 密钥录入框（写入 `plugin:secrets@1` 命名空间 `llm-moderation` 后不回显明文）：
    - **OpenAI Moderation Compat**：`POST /v1/moderations`（`omni-moderation-latest`），支持文本与非 SVG 图片 base64 data URI；内联纯音频/视频显式报错触发回退。
    - **阿里云内容安全 2.0（Green-CIP）**：`green-cip.{region}.aliyuncs.com` + `ACS3-HMAC-SHA256`（`application/x-www-form-urlencoded` RPC `TextModerationPlus`：`llm_query_moderation` / `llm_response_moderation`）；内联原始媒体字节因官方要求 `DescribeUploadToken` + OSS 预上传或公网 URL，直传裸字节会显式报错触发回退。
    - **腾讯云天御（TC3-HMAC-SHA256 `2020-12-29`）**：TMS `TextModeration` + IMS `ImageModeration`（`FileContent`）+ AMS 同步音频 `CreateAudioModerationSyncTask`（`FileFormat` / `FileContent`）；VMS 仅支持异步远程 URL 任务，内联视频字节显式报错触发回退；支持多服务子域自动映射自定义端点。
    - **百度智能云 AIP**：`/oauth/2.0/token` 单飞缓存、`text_censor/v2`、`img_censor/v2`（附带静态/GIF `imgType`）与 `voice_censor/v3/user_defined`（`fmt` / `base64` / `rate=16000`）；`video_censor` 仅支持公网 URL，内联视频字节显式报错触发回退。
- **Ollama 本机/局域网 GPU 托管与 SSRF 边界**：
  - 统一控制台（`/api/moderation/ollama/{status,install,start,pull,test}`）与宿主 CLI（`host-cli.mjs ollama <status|install|start|pull|test>`）支持一键受控安装（需 `confirmInstall: true` 并剥离 LoomWard 密钥环境变量）、仅回环拉起 `ollama serve`、一键拉取推荐安全模型（`llama-guard3:1b` / `8b`、`shieldgemma:2b`、`qwen2.5:0.5b`、`qwen3:0.6b`）与端到端低延迟推理测试。
  - 启用按端点显式勾选的 `allowPrivateNetwork` 后可接入受信任私有局域网 GPU 节点（如 `http://192.168.x.x:11434`），同时无论是否开启均强制阻断 `169.254.169.254` 云元数据、链路本地 IP 与公网明文 `http://`。
- **独立 / 合并 / 流式全覆盖**：
  - `input-only`、`output-only`、`combined`（通过 `InvocationCorrelationStore` 按 `requestId` 关联上下文）。
  - 原生流式门控 `tool:stream@1`：`StreamInspectSession` 实现滑动窗口、跨块 `overlapChars` 重叠检测、`holdbackChars` 尾部暂留释放与命中即时 `abort()`。
- **策略级故障回退（`policyProfile`）**：
  - 支持 `strict`、`balanced`、`experimental-resilient` 三档策略预设与按工具覆盖（`perToolOverrides`）。
- **多模态与按需隔离依赖**：
  - 纯文本 / 云端模式零额外二进制依赖（纯 Python 标准库 + Node.js）。
  - 本机图像 / 音频 / 视频深度预检与清洗（`pillow`、`av`、`faster-whisper`、`rapidocr-onnxruntime`）按模态 fail-closed：未安装对应解码依赖时仅阻断本机该模态，不影响纯文本或云端已授权流程。
- **凭据隔离**：
  - 通过内核绑定 caller 的 `plugin:secrets@1` 仅按需读取对应 Provider 密钥，凭据只在控制台只写托管接口中单向保存。
