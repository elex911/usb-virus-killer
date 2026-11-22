# 离线信任资产（rules/）

引擎不内置任何根证书与吊销名单——它们必须由你在**联网的开发机**导出后放进这里，
再随绿包一起拷到 U 盘。原因很简单：根证书库会变，内置死的必然过期；
而且把"信任谁"变成显式的、可审计的文件，比藏在代码里可靠。

## 目录约定

```
rules/
  roots/      *.cer / *.crt / *.der / *.pem     受信根证书（离线信任锚）
  revoked/    *.json / *.txt                    吊销/黑名单证书指纹
```

## 1. 导出受信根证书

在**联网且管理员**的 Windows 上执行（PowerShell）：

```powershell
$dst = ".\portableav\rules\roots"
New-Item -ItemType Directory -Force -Path $dst | Out-Null
$i = 0
Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object {
    $i++
    [IO.File]::WriteAllBytes((Join-Path $dst ("r{0:D4}.cer" -f $i)), $_.RawData)
}
"导出 $i 张"
```

本机实测为 62 张（Win11 环境，仅作参考，不同系统差异很大）。

## 2. 导出吊销/黑名单

`Cert:\LocalMachine\Disallowed` 在多数机器上是**空的**，不能当作吊销名单来源。
两条可用途径：

**A. 已知被盗/泄露证书的指纹**（手工维护，最实用）写在 `revoked/list.txt`：
一行一个 SHA-1 指纹，允许带空格或冒号，`#` 开头为注释。

**B. 微软官方 disallowed 证书包**（需要联网）：
```powershell
certutil -syncWithWU .\rules\revoked
```
下载得到的 `disallowedcert.sst` 是序列化证书库，需要先转成指纹文本再使用；
直接丢 `.sst` 进来引擎不会解析，只会显示"未启用"。

## 3. 行为约定（重要）

| 情况 | 引擎行为 |
|---|---|
| 没有 `roots/` 或为空 | **任何签名都不判白**，全部落"待复核"；报告里写明"编录不可用" |
| `revoked/` 为空 | 不阻塞扫描，但报告写明"吊销检查未启用"——不假装检查过 |
| 名单里命中链上任意一级证书 | 该签名判**黑**（被盗证书签的马正是这个特征） |
| 名单文件格式错误 | 该文件被忽略，`--blacklist` 输出里会显示条数，便于核对 |

## 4. 取证提示

`roots/` 应尽量用**目标系统同代**的根库（比如目标机是 Win10，就用 Win10 的根库导出）。
用新系统的根去验老系统文件不会误判为恶意，但可能让本应判白的文件落灰。
