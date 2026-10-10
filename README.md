# SecPilot

安全告警证据整理与人工复核工作台。

SecPilot 将 SARIF / JSON 扫描报告中的告警合并、映射到授权样本代码，展示来源、风险解释、修复建议与验证方法，并记录人工复核状态。支持 JSON 和 Markdown 报告导出，以及可选的 Huawei Cloud AgentArts 接口适配。

## 功能

- 解析 SARIF 2.1.0 与标准 JSON 告警。
- 根据分类、文件路径和行号合并重复告警，保留全部原始来源。
- 展示源码证据；找不到源文件时明确提示证据不足。
- 保存待复核、已确认、误报状态及变更历史。
- 导出包含证据、来源和复核状态的报告。
- 云分析需显式同意发送证据，校验返回的 ID、位置与分类；失败时不会伪装成本地成功。

## 快速开始

需要 Python 3.10 或更新版本。本地模式仅使用 Python 标准库，不需要安装第三方依赖。

```bash
git clone https://github.com/Q-w-z/secpilot.git
cd secpilot
python -m backend.server
```

浏览器打开 `http://127.0.0.1:8765`，点击「加载教学样本并分析」。Windows 也可以执行 `scripts/start.ps1`。

默认 `LOCAL_DEMO` 使用固定模板，不调用云模型。随包数据为合成教学样例，不代表真实扫描器输出。当前证据仅映射 `samples/` 目录；不会自动读取任意项目，也不会执行上传代码。

## AgentArts 配置

参见 [接口与输出约定](docs/agentarts.md) 和 [系统提示词示例](docs/agent_system_prompt.txt)。请使用自己的部署地址及环境变量配置凭证。`.env.example` 仅展示字段，程序不会自动加载它。

实际接口调用可能产生服务费用，默认不开启。平台预览与本地 API 适配是两条独立路径，使用者需在自己的部署上完成接口验证。

## 测试与评估

```bash
python -m unittest discover -s tests -v
python scripts/evaluate.py
```

测试使用合成数据和模拟传输，不访问真实云接口。IAM 签名测试需要另外安装华为官方 API 签名 SDK，否则会跳过该项测试。

## 目录

```text
backend/    报告解析、证据映射、复核存储与 HTTP 服务
frontend/   无构建依赖的浏览器工作台
samples/    合成告警及授权教学代码
scripts/    启动、评估与可选云接口验证
tests/      解析、边界与模拟接口测试
docs/       AgentArts 适配与提示词
evidence/   本机运行结果，不纳入版本控制
```

本服务默认仅监听本机回环地址。风险提示不等于确认漏洞；结论须结合授权代码、运行上下文和人工验证。

## License

项目原创代码采用 [MIT License](LICENSE)。可选华为签名 SDK 未随仓库分发，其使用条件以官方发布内容为准。
