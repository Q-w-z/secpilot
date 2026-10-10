# AgentArts 接口适配

适配器位于 `backend/core.py`。配置 `AGENTARTS_INVOKE_URL` 为自己部署的运行时 HTTPS 地址。只接受华为云域名和 `/runtimes/<name>/invocations` 路径，不跟随重定向。

## API Key

设置 `AGENTARTS_AUTH_MODE=api_key` 和 `AGENTARTS_API_KEY`。低代码模式设置 `AGENTARTS_APP_MODE=lowcode`，输入字段使用 `query`；其他模式使用 `input`。

## IAM

设置 `AGENTARTS_AUTH_MODE=iam`、`AGENTARTS_REGION`、`HUAWEICLOUD_SDK_AK` 和 `HUAWEICLOUD_SDK_SK`。从[华为官方 API 签名 SDK 页面](https://support.huaweicloud.com/devg-apisign/api-sign-sdk-python.html)取得 SDK，在项目根目录放置 `apig_sdk/` 包。该可选依赖被 Git 忽略，不属于本项目许可证范围。

## 输出约定

返回体 `output` 应为 JSON 对象或可解析的 JSON 字符串，包含 `explanations` 数组。每项必须包含：`id`、`path`、`line`、`category`、`explanation`、`fix`、`verification`。`recommendation` 可映射为 `fix`。原始证据 ID、位置与分类必须保持不变。

用户必须在工作台明确允许发送证据。缺失证据不会发送；网络失败、返回格式异常或证据字段不匹配会终止调用。成功回执写入本机 `evidence/`，不包含密钥。

命令行验证：`python scripts/verify_agentarts.py`。PowerShell 交互入口为 `scripts/connect_agentarts.ps1` 或 `scripts/connect_agentarts_iam.ps1`。仅在确认自己账号的访问权限和费用后使用。
