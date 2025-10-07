# 🔐 JWTBlast — Ethical JWT Penetration Testing Tool

<p align="center">
  <img alt="Go版本" src="https://img.shields.io/badge/Go-1.21%2B-blue">
  <img alt="平台支持" src="https://img.shields.io/badge/平台-Windows%2FLinux%2FmacOS-green">
  <img alt="开源协议" src="https://img.shields.io/badge/许可-MIT-orange">
  <img alt="JWT安全" src="https://img.shields.io/badge/专注-JWT安全测试-red">
</p>

> 一款专为合法渗透测试设计的 **JWT 安全测试工具**，支持暴力破解、算法混淆、头部注入、`none` 算法绕过等攻击模拟，帮助开发者在授权环境中发现并修复 JWT 实现中的潜在漏洞。

---

## ✨ 核心功能

| 模块 | 描述 |
|------|------|
| **🔐 暴力破解** | 支持对 HS256/384/512 的密钥进行字典爆破，内置多种变换（MD5、Base64） |
| **⚠️ 算法混淆** | 将 RSA 公钥当作对称密钥使用，测试服务端是否错误验证 |
| **🧪 None 算法测试** | 自动生成 `alg:none` 令牌，检测是否接受无签名令牌 |
| **🧪 头部注入** | 支持 `jwk`/`jku`/`kid` 注入，模拟真实攻击路径 |
| **🧵 并发优化** | 多 goroutine 并发验证，支持自定义线程数 |
| **📊 报告输出** | 支持 JSON/HTML 报告，记录所有测试过程与发现 |
| **🛡️ 道德合规** | 在线测试前强制确认，所有操作记录日志，仅用于授权测试 |

---

## 🚀 快速开始

### 1. 安装依赖 & 编译

```bash
# 克隆仓库
git clone https://github.com//JWTBlast.git
cd JWTBlast

# 安装依赖
go mod tidy

# 编译
go build -o jwtblast main.go

# 验证
./jwtblast -h
```

---

## 🧪 使用示例

### 🔐 1. 暴力破解对称密钥
```bash
./jwtblast brute \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --dict /usr/share/wordlists/rockyou.txt \
  --workers 8 \
  --report brute.json
```

### ⚠️ 2. 算法混淆（RSA → HS256）
```bash
./jwtblast confusion \
  --token "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --pubkey pubkey.pem \
  --endpoint https://api.example.com/verify \
  --report confusion.json
```

### 🧪 3. 测试 `none` 算法接受
```bash
./jwtblast none \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --modified-claims '{"isAdmin":true}' \
  --endpoint https://api.example.com/verify \
  --report none.json
```

### 🧪 4. 头部注入（kid 路径遍历）
```bash
./jwtblast inject \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --type kid \
  --value "../../../dev/null" \
  --endpoint https://api.example.com/verify \
  --report inject.json
```

### 🔍 5. 一键全扫描（推荐）
```bash
./jwtblast scan \
  --token "eyJ..." \
  --dict rockyou.txt \
  --pubkey pubkey.pem \
  --endpoint https://api.example.com/verify \
  --report fullscan.json
```

---


---

## 🛠️ 命令一览

| 子命令 | 作用 | 必要参数 |
|--------|------|----------|
| `brute` | 暴力破解对称密钥 | `--token`, `--dict` |
| `none` | 测试 `alg=none` 接受 | `--token` |
| `confusion` | 算法混淆攻击 | `--token`, `--pubkey` |
| `inject` | 头部参数注入 | `--token`, `--type`, `--value` |
| `scan` | 一键全扫描 | `--token` |

---

## ⚙️ 参数详解

| 参数 | 说明 | 示例 |
|------|------|------|
| `--token` | 待测试的 JWT 字符串 | `"eyJhbGciOiJIUzI1NiJ9..."` |
| `--dict` | 字典文件路径 | `/usr/share/wordlists/rockyou.txt` |
| `--pubkey` | RSA 公钥文件（PEM） | `pubkey.pem` |
| `--endpoint` | 在线验证接口 | `https://api.example.com/verify` |
| `--modified-claims` | 自定义 payload（JSON） | `{"isAdmin":true}` |
| `--workers` | 并发协程数 | `8` |
| `--report` | 报告输出路径 | `report.json` |

---

## 🛡️ 道德合规与免责声明

- **仅限授权测试**：仅在您拥有明确测试权限的系统上使用。
- **在线确认**：任何涉及目标服务器的操作均需用户手动确认。
- **日志记录**：所有测试行为默认落盘，便于审计。
- **禁止滥用**：禁止用于未授权访问、数据窃取或其他非法行为。
### 风险与责任
- 使用本工具所产生的任何直接、间接风险与损失（包括但不限于服务异常、数据泄露、法律追责）由使用者自行承担；
- 作者及项目贡献者不对任何滥用行为承担任何法律责任；
- 若您不同意本条款，请立即停止使用并删除本工具。
---

## 📌 安全建议（基于实战总结）

| 漏洞类型 | 建议 |
|----------|------|
| **弱密钥** | 使用 `crypto/rand` 生成 256-bit 随机密钥 |
| **none 算法** | 强制拒绝 `alg=none` 令牌 |
| **算法混淆** | 明确区分对称与非对称算法，禁止混用 |
| **头部注入** | 对 `jku`/`jwk`/`kid` 进行白名单校验 |
| **令牌有效期** | 设置短有效期（<15 min）并启用刷新机制 |

---

## 🧩 项目结构

```
JWTBlast/
├── main.go                 # CLI 入口
├── internal/
│   ├── brute/             # 暴力破解模块
│   ├── confusion/         # 算法混淆
│   ├── none/              # none 算法测试
│   ├── inject/            # 头部注入
│   └── report/            # 报告生成
├── wordlists/             # 示例字典
├── README.md
└── LICENSE
```

---

## 🤝 贡献与反馈

欢迎提交 Issue 和 Pull Request！  
请确保所有测试均在授权环境中进行，并遵守当地法律法规。

---

## 📄 开源许可

MIT License — 详见 [LICENSE](LICENSE)

---

**🔐 用 JWTBlast 找出你系统中的 JWT 隐患，守护用户数据安全！**
