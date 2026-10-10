# Enter secrets locally. No secret is echoed, written to disk, or added to a command line.
$ErrorActionPreference='Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
$invokeUrl=Read-Host '粘贴控制台真实高代码运行时调用URL'
$secureKey=Read-Host '输入AgentArts API Key（隐藏输入）' -AsSecureString
$ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
try{
 $env:AGENTARTS_INVOKE_URL=$invokeUrl
 $env:AGENTARTS_API_KEY=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
 $runtimePython='python'
 if(Test-Path -LiteralPath $runtimePython){& $runtimePython scripts/verify_agentarts.py}else{python scripts/verify_agentarts.py}
 if($LASTEXITCODE -ne 0){throw '真实平台验证未通过，请检查运行时、模型配置和输出约定。'}
 Write-Output '真实调用验证通过，即将启动同一配置的本机工作台。'
 if(Test-Path -LiteralPath $runtimePython){& $runtimePython -m backend.server}else{python -m backend.server}
}finally{
 [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
 Remove-Item Env:AGENTARTS_API_KEY -ErrorAction SilentlyContinue
}
