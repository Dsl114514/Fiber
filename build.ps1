# Fiber 构建脚本(D9 工具链:C++20 / MSVC / CMake + Ninja,/MT,警告即错误)
#
#   .\build.ps1                 # Release 构建
#   .\build.ps1 -Config Debug   # Debug 构建
#   .\build.ps1 -Clean          # 先清空 build\
#
# 产物在 build\dist\

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')] [string]$Config = 'Release',
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$root   = $PSScriptRoot
$build  = Join-Path $root 'build'
$cmake  = 'D:\Program Files\CMake\bin\cmake.exe'
$ninja  = 'E:\ninja-win\ninja.exe'
$vcvars = 'E:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat'

foreach ($p in @($cmake, $ninja, $vcvars)) {
    if (-not (Test-Path $p)) { throw "缺少构建依赖: $p" }
}

if ($Clean -and (Test-Path $build)) {
    Write-Host '[0/3] 清空 build\ ...' -ForegroundColor DarkGray
    Remove-Item -Recurse -Force $build
}

# 把 MSVC 开发者环境导入当前会话
Write-Host '[1/3] 导入 MSVC 环境 ...' -ForegroundColor Cyan
$envDump = & cmd.exe /c "`"$vcvars`" >nul 2>&1 && set"
if ($LASTEXITCODE -ne 0) { throw "vcvars64.bat 执行失败($LASTEXITCODE)" }
foreach ($line in $envDump) {
    $i = $line.IndexOf('=')
    if ($i -le 0) { continue }
    $name = $line.Substring(0, $i)
    if ($name.StartsWith('=')) { continue }   # 跳过 "=C:" 这类内部变量
    Set-Item -Path "env:$name" -Value $line.Substring($i + 1)
}

Write-Host "[2/3] CMake 配置 ($Config) ..." -ForegroundColor Cyan
& $cmake -S $root -B $build -G Ninja `
    "-DCMAKE_BUILD_TYPE=$Config" `
    "-DCMAKE_MAKE_PROGRAM=$ninja" `
    '-DCMAKE_C_COMPILER=cl' `
    '-DCMAKE_CXX_COMPILER=cl'
if ($LASTEXITCODE -ne 0) { throw "CMake 配置失败($LASTEXITCODE)" }

Write-Host '[3/3] 构建 ...' -ForegroundColor Cyan
& $cmake --build $build
if ($LASTEXITCODE -ne 0) { throw "构建失败($LASTEXITCODE)" }

$dist = Join-Path $build 'dist'
Write-Host "`n产物 ($dist):" -ForegroundColor Green
Get-ChildItem $dist -ErrorAction SilentlyContinue | Select-Object Name, Length | Format-Table -AutoSize