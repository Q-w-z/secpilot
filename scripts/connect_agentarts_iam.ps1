# Credentials stay in this process and its Python child. Never echo or save them.
$ErrorActionPreference='Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
$runtimePython='python'
$invokeUrl=Read-Host '输入你自己的 AgentArts 运行时 HTTPS 调用地址'
$region=Read-Host '输入运行时所在区域'
Write-Host 'SecPilot：连接已部署的 AgentArts IAM 运行时'
Write-Host '只发送本项目合成样本，调用一次，不自动重试。'
$decision=Read-Host 'API 模型调用可能计费。确认允许本次调用请输入 CALL；其他输入退出'
if($decision -cne 'CALL'){exit 0}
$secureAk=Read-Host '输入华为云访问密钥 AK（隐藏输入）' -AsSecureString
$secureSk=Read-Host '输入对应 SK（隐藏输入）' -AsSecureString
$akPtr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAk)
$skPtr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSk)
try {
 $env:AGENTARTS_AUTH_MODE='iam'
 $env:AGENTARTS_APP_MODE='lowcode'
 $env:AGENTARTS_REGION=$region
 $env:AGENTARTS_INVOKE_URL=$invokeUrl
 $env:HUAWEICLOUD_SDK_AK=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($akPtr)
 $env:HUAWEICLOUD_SDK_SK=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($skPtr)
 & $runtimePython scripts/verify_agentarts.py
 if($LASTEXITCODE -ne 0){throw '本次验证未通过，已停止；不会自动重试或转成本地成功。'}
 Write-Host '真实接口和证据字段验证通过。回执已保存到 evidence。'
 Read-Host '按回车结束并清除本进程凭证'
} finally {
 [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($akPtr)
 [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($skPtr)
 Remove-Item Env:HUAWEICLOUD_SDK_AK -ErrorAction SilentlyContinue
 Remove-Item Env:HUAWEICLOUD_SDK_SK -ErrorAction SilentlyContinue
}
