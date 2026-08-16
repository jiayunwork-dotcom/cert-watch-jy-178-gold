# cert-watch 示例

扫描本地 X.509 证书（PEM/CRT/DER，支持单文件、目录、glob），报告每张证书的
剩余天数并标记状态。完全离线，不连接 CA 或网络。

本目录已用 `openssl` 生成 3 张样例证书，方便直接试跑：

| 文件 | 状态 |
|------|------|
| `valid.pem` | 约 400 天后到期 → OK |
| `warn.pem`  | 约 15 天后到期 → WARN |
| `expired.pem` | 已过期 → EXPIRED |

## 扫描目录

```bash
go run . -in example/
```

## 扫描单个文件 / glob

```bash
go run . -in example/warn.pem
go run . -in "example/*.pem"
```

## 调整告警窗口 + 严格模式（有问题则 exit 1，适合接入 cron/监控）

```bash
go run . -in example/ -warn 30 -strict
```

> 缺 `-in` 或路径不存在 → 受控报错（exit 1），不 panic。
> `-strict` 下只要有 WARN/EXPIRED 就会以 `exit 1` 退出，便于监控脚本判断。
