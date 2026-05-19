# 🛡️ EnvShield

[English](#english) | [简体中文](#简体中文) | [繁體中文](#繁體中文)

> Lightweight Environment Variable Security Management CLI Engine

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version" />
  <img src="https://img.shields.io/badge/python-3.8+-green.svg" alt="Python" />
  <img src="https://img.shields.io/badge/license-MIT-orange.svg" alt="License" />
  <img src="https://img.shields.io/badge/encryption-AES--256--GCM-red.svg" alt="Encryption" />
</p>

---

## 简体中文

### 🎉 项目介绍

EnvShield 是一款轻量级环境变量安全管理 CLI 引擎，专为保护应用程序敏感配置而设计。

**为什么需要 EnvShield？**

在日常开发中，我们经常面临以下痛点：

- `.env` 文件以明文存储在项目目录中，任何拥有代码访问权限的人都能看到数据库密码、API 密钥等敏感信息
- 团队协作时，密钥通过即时通讯工具或邮件传递，存在泄露风险
- 缺乏系统化的安全审计手段，难以评估当前环境配置的安全水位
- 源码中偶尔残留硬编码的密钥，成为安全隐患的定时炸弹
- 多环境（开发、测试、生产）的配置管理混乱，容易误操作

**核心价值：** 用一行命令完成环境变量的加密保护，用一套规则实现安全审计自动化，用零侵入的方式融入现有开发流程。

**差异化亮点：**

- 🔐 **零配置启动** — 无需复杂设置，`envshield init` 即刻上手
- ⚡ **极致轻量** — 核心依赖仅 `cryptography`、`rich`、`click` 三个库
- 🔄 **无缝集成** — Git 钩子自动拦截，运行时透明解密注入
- 📊 **量化安全** — 15 条审计规则输出 0-100 安全评分，安全状况一目了然

---

### ✨ 核心特性

| 特性 | 说明 |
|------|------|
| 🔒 **AES-256-GCM 加密** | 采用军事级加密算法保护 `.env` 文件，支持认证加密，防篡改 |
| 🔍 **安全审计引擎** | 内置 15 条安全规则，输出 0-100 安全评分及详细改进建议 |
| 🕵️ **源码扫描器** | 智能检测 20+ 种硬编码密钥模式，覆盖 Python、JS、Go、Java 等主流语言 |
| 🪝 **Git 钩子守护** | 自动安装 pre-commit 钩子，从源头阻止 `.env` 文件被提交到代码仓库 |
| 🌍 **多环境管理** | 支持 dev / staging / prod 多环境配置切换，告别环境混乱 |
| 📊 **TUI 可视化仪表盘** | 基于 Rich 构建的终端仪表盘，直观展示安全状态概览 |
| 💉 **运行时内存解密** | 解密后的变量仅存在于进程内存中，不落盘，不留痕 |
| 📤 **格式导入导出** | 支持 JSON / YAML 格式导出导入，方便跨平台迁移和备份 |

---

### 🚀 快速开始

#### 环境要求

- Python 3.8 或更高版本
- pip 包管理器

#### 安装

```bash
# 通过 pip 安装
pip install envshield

# 验证安装
envshield --version
```

#### 三步上手

```bash
# 第一步：在项目根目录初始化
envshield init

# 第二步：加密你的 .env 文件
envshield encrypt .env

# 第三步：运行安全审计，查看安全评分
envshield audit .env
```

加密后会生成 `.env.vault` 文件，原始 `.env` 文件将被安全删除。你可以放心地将 `.env.vault` 提交到代码仓库。

---

### 📖 详细使用指南

#### 🔒 加密与解密

```bash
# 加密 .env 文件（默认）
envshield encrypt .env

# 加密指定文件
envshield encrypt /path/to/production.env

# 解密 .env.vault 文件
envshield decrypt .env.vault

# 解密到指定输出文件
envshield decrypt .env.vault --output .env.local
```

加密流程说明：
1. 读取原始 `.env` 文件内容
2. 使用 AES-256-GCM 算法加密
3. 生成 `.env.vault` 加密文件
4. 安全擦除原始 `.env` 文件
5. 自动将 `.env.vault` 添加到 `.gitignore`（可选）

#### 🔍 安全审计

```bash
# 对当前 .env 文件进行审计
envshield audit .env

# 审计并输出 JSON 格式报告
envshield audit .env --format json --output report.json

# 审计指定目录下所有 .env 文件
envshield audit ./config/
```

审计输出示例：

```
╭─────────────────────────────────────────────╮
│           EnvShield 安全审计报告              │
├─────────────────────────────────────────────┤
│  综合安全评分:  72 / 100  ⚠️ 中等风险        │
│  审计规则数:    15 条                        │
│  通过规则:      11 条  ✅                    │
│  警告规则:      3 条   ⚠️                    │
│  未通过规则:    1 条   ❌                    │
╰─────────────────────────────────────────────╯
```

#### 🕵️ 源码扫描

```bash
# 扫描当前目录
envshield scan .

# 扫描指定目录，排除 node_modules
envshield scan ./src --exclude node_modules,venv,.git

# 扫描并输出详细报告
envshield scan ./src --verbose
```

源码扫描器支持检测以下模式：
- 硬编码的 API Key（`api_key = "sk-..."`）
- 数据库连接字符串中的明文密码
- AWS / GCP / Azure 凭证
- JWT 密钥、OAuth Token
- 私钥文件内容
- 其他 20+ 种常见密钥泄露模式

#### 🪝 Git 钩子

```bash
# 安装 pre-commit 钩子
envshield hook install

# 卸载钩子
envshield hook uninstall
```

安装后，每次 `git commit` 时会自动检测暂存区中是否包含 `.env` 文件。如果检测到，提交将被阻止并提示用户。

#### 📊 TUI 仪表盘

```bash
# 打开交互式仪表盘
envshield dashboard
```

仪表盘提供以下视图：
- 环境变量总览（加密/明文状态）
- 安全评分趋势图
- 最近审计历史
- 密钥轮换提醒

#### 🔑 变量管理

```bash
# 设置变量
envshield set DATABASE_URL "postgres://user:pass@localhost:5432/mydb"

# 获取变量
envshield get DATABASE_URL

# 列出所有变量
envshield list

# 删除变量
envshield delete API_KEY
```

#### 🌍 环境切换

```bash
# 切换到生产环境
envshield switch prod

# 切换到开发环境
envshield switch dev

# 查看当前环境
envshield switch --current
```

---

### 💡 安全审计规则

EnvShield 内置 15 条安全审计规则，覆盖密钥强度、文件权限、泄露检测等多个维度：

| # | 规则名称 | 说明 | 严重级别 |
|---|---------|------|---------|
| 1 | **弱密钥检测** | 检查密钥长度是否低于 16 个字符 | 🔴 高 |
| 2 | **常见弱密钥匹配** | 检测是否使用 `password`、`123456` 等常见弱密钥 | 🔴 高 |
| 3 | **密钥熵值评估** | 评估密钥的随机性和复杂度 | 🟡 中 |
| 4 | **明文密码检测** | 检查连接字符串中是否包含明文密码 | 🔴 高 |
| 5 | **API Key 格式验证** | 验证 API Key 是否符合服务商格式规范 | 🟡 中 |
| 6 | **过期密钥检测** | 检查密钥是否超过建议轮换周期（90 天） | 🟡 中 |
| 7 | **文件权限检查** | 检查 `.env` 文件权限是否过于宽松 | 🔴 高 |
| 8 | **.gitignore 覆盖检查** | 确认 `.env` 文件已被 `.gitignore` 排除 | 🔴 高 |
| 9 | **重复密钥检测** | 检查不同环境间是否存在相同密钥 | 🟡 中 |
| 10 | **敏感变量命名规范** | 检查敏感变量是否使用 `SECRET`、`KEY`、`TOKEN` 等后缀 | 🟢 低 |
| 11 | **硬编码凭证扫描** | 扫描源码中是否存在硬编码的凭证 | 🔴 高 |
| 12 | **调试模式检测** | 检查是否在生产环境开启了调试模式 | 🟡 中 |
| 13 | **不安全协议检测** | 检查连接字符串是否使用 HTTP 等不安全协议 | 🟡 中 |
| 14 | **默认凭证检测** | 检查是否使用了框架默认凭证 | 🔴 高 |
| 15 | **密钥轮换策略** | 评估密钥轮换策略的完善程度 | 🟢 低 |

---

### 📦 进阶用法

#### 多环境管理

```bash
# 初始化多环境配置
envshield init --envs dev,staging,prod

# 为不同环境设置变量
envshield set DATABASE_URL "postgres://localhost/dev" --env dev
envshield set DATABASE_URL "postgres://staging-db/app" --env staging
envshield set DATABASE_URL "postgres://prod-db/app" --env prod

# 切换环境
envshield switch prod
```

#### 运行时解密注入

```bash
# 使用运行时注入启动应用
envshield run -- python app.py

# 使用运行时注入启动 Node.js 应用
envshield run -- node server.js

# 使用运行时注入执行任意命令
envshield run -- make deploy
```

运行时注入的工作原理：
1. 读取 `.env.vault` 加密文件
2. 在进程内存中解密
3. 将解密后的变量注入到子进程的环境变量中
4. 解密数据仅存在于内存中，进程结束后自动清除

#### CI/CD 集成

```yaml
# GitHub Actions 示例
- name: Setup EnvShield
  run: pip install envshield

- name: Decrypt environment
  run: envshield decrypt .env.vault --output .env
  env:
    ENVSHIELD_MASTER_KEY: ${{ secrets.ENVSHIELD_MASTER_KEY }}

- name: Run security audit
  run: envshield audit .env --format json --output audit-report.json

- name: Scan source code
  run: envshield scan ./src --exclude node_modules,venv
```

```yaml
# GitLab CI 示例
security_audit:
  stage: test
  before_script:
    - pip install envshield
  script:
    - envshield decrypt .env.vault --output .env
    - envshield audit .env
    - envshield scan ./src
  artifacts:
    reports:
      security_audit: audit-report.json
```

#### 导出与导入

```bash
# 导出为 JSON 格式
envshield export --format json --output config.json

# 导出为 YAML 格式
envshield export --format yaml --output config.yaml

# 从 JSON 导入
envshield import config.json

# 从 YAML 导入
envshield import config.yaml
```

---

### 🤝 贡献指南

我们欢迎并感谢每一位贡献者！在参与贡献之前，请阅读以下规范：

#### 提交 Pull Request

1. **Fork** 本仓库并创建你的特性分支：`git checkout -b feature/amazing-feature`
2. **编写代码** 并确保通过所有测试：`pytest tests/`
3. **提交变更**，使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：`git commit -m 'feat: add amazing feature'`
4. **推送** 到你的 Fork：`git push origin feature/amazing-feature`
5. 创建 **Pull Request** 并详细描述变更内容

#### 提交 Issue

- 使用清晰的标题描述问题
- 附上复现步骤和期望行为
- 附上运行环境信息（操作系统、Python 版本、EnvShield 版本）
- 如有可能，附上错误日志截图

#### 代码规范

- 遵循 PEP 8 编码规范
- 所有公共函数必须包含文档字符串
- 新功能必须附带对应的单元测试
- 安全相关代码变更需要经过额外的代码审查

---

### 📄 开源协议

本项目基于 [MIT 协议](https://opensource.org/licenses/MIT) 开源。

```
MIT License

Copyright (c) 2024 EnvShield Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 繁體中文

### 🎉 專案介紹

EnvShield 是一款輕量級環境變數安全管理 CLI 引擎，專為保護應用程式敏感設定而設計。

**為什麼需要 EnvShield？**

在日常開發中，我們經常面臨以下痛點：

- `.env` 檔案以明文儲存在專案目錄中，任何擁有程式碼存取權限的人都能看到資料庫密碼、API 金鑰等敏感資訊
- 團隊協作時，金鑰透過通訊軟體或電子郵件傳遞，存在外洩風險
- 缺乏系統化的安全稽核手段，難以評估目前環境設定的安全水位
- 原始碼中偶爾殘留硬編碼的金鑰，成為安全隱患的定時炸彈
- 多環境（開發、測試、正式）的設定管理混亂，容易誤操作

**核心價值：** 用一行指令完成環境變數的加密保護，用一套規則實現安全稽核自動化，用零侵入的方式融入現有開發流程。

**差異化亮點：**

- 🔐 **零設定啟動** — 無需繁瑣設定，`envshield init` 即刻上手
- ⚡ **極致輕量** — 核心依賴僅 `cryptography`、`rich`、`click` 三個函式庫
- 🔄 **無縫整合** — Git 攔截器自動防護，執行期透明解密注入
- 📊 **量化安全** — 15 條稽核規則輸出 0-100 安全評分，安全狀況一目瞭然

---

### ✨ 核心特性

| 特性 | 說明 |
|------|------|
| 🔒 **AES-256-GCM 加密** | 採用軍事級加密演算法保護 `.env` 檔案，支援認證加密，防竄改 |
| 🔍 **安全稽核引擎** | 內建 15 條安全規則，輸出 0-100 安全評分及詳細改善建議 |
| 🕵️ **原始碼掃描器** | 智慧偵測 20+ 種硬編碼金鑰模式，涵蓋 Python、JS、Go、Java 等主流語言 |
| 🪝 **Git 攔截器守護** | 自動安裝 pre-commit 攔截器，從源頭阻止 `.env` 檔案被提交到程式碼倉庫 |
| 🌍 **多環境管理** | 支援 dev / staging / prod 多環境設定切換，告別環境混亂 |
| 📊 **TUI 視覺化儀表板** | 基於 Rich 建構的終端儀表板，直觀展示安全狀態總覽 |
| 💉 **執行期記憶體解密** | 解密後的變數僅存在於行程記憶體中，不落碟，不留痕 |
| 📤 **格式匯入匯出** | 支援 JSON / YAML 格式匯出匯入，方便跨平台遷移與備份 |

---

### 🚀 快速開始

#### 環境需求

- Python 3.8 或更高版本
- pip 套件管理器

#### 安裝

```bash
# 透過 pip 安裝
pip install envshield

# 驗證安裝
envshield --version
```

#### 三步上手

```bash
# 第一步：在專案根目錄初始化
envshield init

# 第二步：加密你的 .env 檔案
envshield encrypt .env

# 第三步：執行安全稽核，查看安全評分
envshield audit .env
```

加密後會產生 `.env.vault` 檔案，原始 `.env` 檔案將被安全刪除。你可以放心地將 `.env.vault` 提交到程式碼倉庫。

---

### 📖 詳細使用指南

#### 🔒 加密與解密

```bash
# 加密 .env 檔案（預設）
envshield encrypt .env

# 加密指定檔案
envshield encrypt /path/to/production.env

# 解密 .env.vault 檔案
envshield decrypt .env.vault

# 解密到指定輸出檔案
envshield decrypt .env.vault --output .env.local
```

加密流程說明：
1. 讀取原始 `.env` 檔案內容
2. 使用 AES-256-GCM 演算法加密
3. 產生 `.env.vault` 加密檔案
4. 安全清除原始 `.env` 檔案
5. 自動將 `.env.vault` 加入 `.gitignore`（可選）

#### 🔍 安全稽核

```bash
# 對目前 .env 檔案進行稽核
envshield audit .env

# 稽核並輸出 JSON 格式報告
envshield audit .env --format json --output report.json

# 稽核指定目錄下所有 .env 檔案
envshield audit ./config/
```

稽核輸出範例：

```
╭─────────────────────────────────────────────╮
│           EnvShield 安全稽核報告              │
├─────────────────────────────────────────────┤
│  綜合安全評分:  72 / 100  ⚠️ 中等風險        │
│  稽核規則數:    15 條                        │
│  通過規則:      11 條  ✅                    │
│  警告規則:      3 條   ⚠️                    │
│  未通過規則:    1 條   ❌                    │
╰─────────────────────────────────────────────╯
```

#### 🕵️ 原始碼掃描

```bash
# 掃描目前目錄
envshield scan .

# 掃描指定目錄，排除 node_modules
envshield scan ./src --exclude node_modules,venv,.git

# 掃描並輸出詳細報告
envshield scan ./src --verbose
```

原始碼掃描器支援偵測以下模式：
- 硬編碼的 API Key（`api_key = "sk-..."`）
- 資料庫連線字串中的明文密碼
- AWS / GCP / Azure 憑證
- JWT 金鑰、OAuth Token
- 私鑰檔案內容
- 其他 20+ 種常見金鑰外洩模式

#### 🪝 Git 攔截器

```bash
# 安裝 pre-commit 攔截器
envshield hook install

# 卸載攔截器
envshield hook uninstall
```

安裝後，每次 `git commit` 時會自動偵測暫存區中是否包含 `.env` 檔案。如果偵測到，提交將被阻止並提示使用者。

#### 📊 TUI 儀表板

```bash
# 開啟互動式儀表板
envshield dashboard
```

儀表板提供以下檢視：
- 環境變數總覽（加密/明文狀態）
- 安全評分趨勢圖
- 最近稽核歷史
- 金鑰輪換提醒

#### 🔑 變數管理

```bash
# 設定變數
envshield set DATABASE_URL "postgres://user:pass@localhost:5432/mydb"

# 取得變數
envshield get DATABASE_URL

# 列出所有變數
envshield list

# 刪除變數
envshield delete API_KEY
```

#### 🌍 環境切換

```bash
# 切換到正式環境
envshield switch prod

# 切換到開發環境
envshield switch dev

# 查看目前環境
envshield switch --current
```

---

### 💡 安全稽核規則

EnvShield 內建 15 條安全稽核規則，涵蓋金鑰強度、檔案權限、外洩偵測等多個維度：

| # | 規則名稱 | 說明 | 嚴重等級 |
|---|---------|------|---------|
| 1 | **弱金鑰偵測** | 檢查金鑰長度是否低於 16 個字元 | 🔴 高 |
| 2 | **常見弱金鑰比對** | 偵測是否使用 `password`、`123456` 等常見弱金鑰 | 🔴 高 |
| 3 | **金鑰熵值評估** | 評估金鑰的隨機性與複雜度 | 🟡 中 |
| 4 | **明文密碼偵測** | 檢查連線字串中是否包含明文密碼 | 🔴 高 |
| 5 | **API Key 格式驗證** | 驗證 API Key 是否符合服務商格式規範 | 🟡 中 |
| 6 | **過期金鑰偵測** | 檢查金鑰是否超過建議輪換週期（90 天） | 🟡 中 |
| 7 | **檔案權限檢查** | 檢查 `.env` 檔案權限是否過於寬鬆 | 🔴 高 |
| 8 | **.gitignore 覆蓋檢查** | 確認 `.env` 檔案已被 `.gitignore` 排除 | 🔴 高 |
| 9 | **重複金鑰偵測** | 檢查不同環境間是否存在相同金鑰 | 🟡 中 |
| 10 | **敏感變數命名規範** | 檢查敏感變數是否使用 `SECRET`、`KEY`、`TOKEN` 等後綴 | 🟢 低 |
| 11 | **硬編碼憑證掃描** | 掃描原始碼中是否存在硬編碼的憑證 | 🔴 高 |
| 12 | **除錯模式偵測** | 檢查是否在正式環境開啟了除錯模式 | 🟡 中 |
| 13 | **不安全協定偵測** | 棢查連線字串是否使用 HTTP 等不安全協定 | 🟡 中 |
| 14 | **預設憑證偵測** | 檢查是否使用了框架預設憑證 | 🔴 高 |
| 15 | **金鑰輪換策略** | 評估金鑰輪換策略的完善程度 | 🟢 低 |

---

### 📦 進階用法

#### 多環境管理

```bash
# 初始化多環境設定
envshield init --envs dev,staging,prod

# 為不同環境設定變數
envshield set DATABASE_URL "postgres://localhost/dev" --env dev
envshield set DATABASE_URL "postgres://staging-db/app" --env staging
envshield set DATABASE_URL "postgres://prod-db/app" --env prod

# 切換環境
envshield switch prod
```

#### 執行期解密注入

```bash
# 使用執行期注入啟動應用程式
envshield run -- python app.py

# 使用執行期注入啟動 Node.js 應用程式
envshield run -- node server.js

# 使用執行期注入執行任意指令
envshield run -- make deploy
```

執行期注入的工作原理：
1. 讀取 `.env.vault` 加密檔案
2. 在行程記憶體中解密
3. 將解密後的變數注入到子行程的環境變數中
4. 解密資料僅存在於記憶體中，行程結束後自動清除

#### CI/CD 整合

```yaml
# GitHub Actions 範例
- name: Setup EnvShield
  run: pip install envshield

- name: Decrypt environment
  run: envshield decrypt .env.vault --output .env
  env:
    ENVSHIELD_MASTER_KEY: ${{ secrets.ENVSHIELD_MASTER_KEY }}

- name: Run security audit
  run: envshield audit .env --format json --output audit-report.json

- name: Scan source code
  run: envshield scan ./src --exclude node_modules,venv
```

```yaml
# GitLab CI 範例
security_audit:
  stage: test
  before_script:
    - pip install envshield
  script:
    - envshield decrypt .env.vault --output .env
    - envshield audit .env
    - envshield scan ./src
  artifacts:
    reports:
      security_audit: audit-report.json
```

#### 匯出與匯入

```bash
# 匯出為 JSON 格式
envshield export --format json --output config.json

# 匯出為 YAML 格式
envshield export --format yaml --output config.yaml

# 從 JSON 匯入
envshield import config.json

# 從 YAML 匯入
envshield import config.yaml
```

---

### 🤝 貢獻指南

我們歡迎並感謝每一位貢獻者！在參與貢獻之前，請閱讀以下規範：

#### 提交 Pull Request

1. **Fork** 本倉庫並建立你的功能分支：`git checkout -b feature/amazing-feature`
2. **撰寫程式碼** 並確保通過所有測試：`pytest tests/`
3. **提交變更**，使用 [Conventional Commits](https://www.conventionalcommits.org/) 規範：`git commit -m 'feat: add amazing feature'`
4. **推送** 到你的 Fork：`git push origin feature/amazing-feature`
5. 建立 **Pull Request** 並詳細描述變更內容

#### 提交 Issue

- 使用清晰的標題描述問題
- 附上重現步驟與期望行為
- 附上執行環境資訊（作業系統、Python 版本、EnvShield 版本）
- 如有可能，附上錯誤日誌截圖

#### 程式碼規範

- 遵循 PEP 8 編碼規範
- 所有公共函式必須包含文件字串
- 新功能必須附帶對應的單元測試
- 安全相關程式碼變更需要經過額外的程式碼審查

---

### 📄 開源授權

本專案基於 [MIT 授權](https://opensource.org/licenses/MIT) 開源。

```
MIT License

Copyright (c) 2024 EnvShield Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## English

### 🎉 Introduction

EnvShield is a lightweight environment variable security management CLI engine designed to protect sensitive application configurations.

**Why EnvShield?**

In day-to-day development, we frequently encounter the following pain points:

- `.env` files are stored in plaintext within project directories, exposing database passwords, API keys, and other sensitive information to anyone with code access
- During team collaboration, secrets are shared via messaging apps or email, creating leakage risks
- There is a lack of systematic security auditing, making it difficult to assess the security posture of environment configurations
- Hardcoded secrets occasionally remain in source code, acting as ticking time bombs for security breaches
- Multi-environment (development, staging, production) configuration management is chaotic and error-prone

**Core Value:** Encrypt environment variables with a single command, automate security auditing with a comprehensive rule set, and seamlessly integrate into existing development workflows with zero intrusion.

**Key Differentiators:**

- 🔐 **Zero-config startup** — No complex setup required; get started instantly with `envshield init`
- ⚡ **Ultra-lightweight** — Only three core dependencies: `cryptography`, `rich`, and `click`
- 🔄 **Seamless integration** — Git hooks for automatic interception, transparent runtime decryption injection
- 📊 **Quantified security** — 15 auditing rules output a 0-100 security score for at-a-glance assessment

---

### ✨ Core Features

| Feature | Description |
|---------|-------------|
| 🔒 **AES-256-GCM Encryption** | Military-grade authenticated encryption for `.env` files with tamper protection |
| 🔍 **Security Audit Engine** | 15 built-in security rules with a 0-100 security score and actionable improvement suggestions |
| 🕵️ **Source Code Scanner** | Intelligent detection of 20+ hardcoded secret patterns across Python, JS, Go, Java, and more |
| 🪝 **Git Hook Guardian** | Automatically installed pre-commit hooks prevent `.env` files from being committed to repositories |
| 🌍 **Multi-environment Management** | Switch between dev / staging / prod configurations effortlessly |
| 📊 **TUI Visual Dashboard** | Rich-based terminal dashboard for an intuitive overview of your security posture |
| 💉 **Runtime In-memory Decryption** | Decrypted variables exist only in process memory — never written to disk |
| 📤 **Format Import/Export** | JSON / YAML format support for cross-platform migration and backup |

---

### 🚀 Quick Start

#### Prerequisites

- Python 3.8 or later
- pip package manager

#### Installation

```bash
# Install via pip
pip install envshield

# Verify installation
envshield --version
```

#### Three Steps to Get Started

```bash
# Step 1: Initialize in your project root
envshield init

# Step 2: Encrypt your .env file
envshield encrypt .env

# Step 3: Run a security audit and check your score
envshield audit .env
```

After encryption, a `.env.vault` file is generated and the original `.env` file is securely deleted. You can safely commit `.env.vault` to your repository.

---

### 📖 Detailed Usage Guide

#### 🔒 Encryption & Decryption

```bash
# Encrypt .env file (default)
envshield encrypt .env

# Encrypt a specific file
envshield encrypt /path/to/production.env

# Decrypt .env.vault file
envshield decrypt .env.vault

# Decrypt to a specific output file
envshield decrypt .env.vault --output .env.local
```

Encryption workflow:
1. Read the original `.env` file contents
2. Encrypt using the AES-256-GCM algorithm
3. Generate a `.env.vault` encrypted file
4. Securely erase the original `.env` file
5. Automatically add `.env.vault` to `.gitignore` (optional)

#### 🔍 Security Audit

```bash
# Audit the current .env file
envshield audit .env

# Audit and output a JSON report
envshield audit .env --format json --output report.json

# Audit all .env files in a directory
envshield audit ./config/
```

Sample audit output:

```
╭─────────────────────────────────────────────╮
│         EnvShield Security Audit Report      │
├─────────────────────────────────────────────┤
│  Overall Score:  72 / 100  ⚠️ Medium Risk   │
│  Rules Checked:  15                          │
│  Passed:         11  ✅                      │
│  Warnings:       3   ⚠️                      │
│  Failed:         1   ❌                      │
╰─────────────────────────────────────────────╯
```

#### 🕵️ Source Code Scanning

```bash
# Scan the current directory
envshield scan .

# Scan a specific directory, excluding node_modules
envshield scan ./src --exclude node_modules,venv,.git

# Scan with verbose output
envshield scan ./src --verbose
```

The source code scanner detects the following patterns:
- Hardcoded API keys (`api_key = "sk-..."`)
- Plaintext passwords in database connection strings
- AWS / GCP / Azure credentials
- JWT secrets, OAuth tokens
- Private key file contents
- 20+ other common secret leakage patterns

#### 🪝 Git Hooks

```bash
# Install pre-commit hook
envshield hook install

# Uninstall hook
envshield hook uninstall
```

Once installed, every `git commit` automatically checks the staging area for `.env` files. If detected, the commit is blocked and the user is notified.

#### 📊 TUI Dashboard

```bash
# Open the interactive dashboard
envshield dashboard
```

The dashboard provides the following views:
- Environment variable overview (encrypted/plaintext status)
- Security score trend chart
- Recent audit history
- Key rotation reminders

#### 🔑 Variable Management

```bash
# Set a variable
envshield set DATABASE_URL "postgres://user:pass@localhost:5432/mydb"

# Get a variable
envshield get DATABASE_URL

# List all variables
envshield list

# Delete a variable
envshield delete API_KEY
```

#### 🌍 Environment Switching

```bash
# Switch to production environment
envshield switch prod

# Switch to development environment
envshield switch dev

# View current environment
envshield switch --current
```

---

### 💡 Security Audit Rules

EnvShield includes 15 built-in security audit rules covering key strength, file permissions, leakage detection, and more:

| # | Rule | Description | Severity |
|---|------|-------------|----------|
| 1 | **Weak Key Detection** | Checks if key length is below 16 characters | 🔴 High |
| 2 | **Common Weak Key Match** | Detects use of `password`, `123456`, and other common weak keys | 🔴 High |
| 3 | **Key Entropy Evaluation** | Evaluates the randomness and complexity of keys | 🟡 Medium |
| 4 | **Plaintext Password Detection** | Checks for plaintext passwords in connection strings | 🔴 High |
| 5 | **API Key Format Validation** | Validates API keys against provider format specifications | 🟡 Medium |
| 6 | **Expired Key Detection** | Checks if keys exceed the recommended rotation period (90 days) | 🟡 Medium |
| 7 | **File Permission Check** | Checks if `.env` file permissions are too permissive | 🔴 High |
| 8 | **.gitignore Coverage Check** | Confirms `.env` files are excluded in `.gitignore` | 🔴 High |
| 9 | **Duplicate Key Detection** | Checks for identical keys across different environments | 🟡 Medium |
| 10 | **Sensitive Variable Naming** | Checks if sensitive variables use `SECRET`, `KEY`, `TOKEN` suffixes | 🟢 Low |
| 11 | **Hardcoded Credential Scan** | Scans source code for hardcoded credentials | 🔴 High |
| 12 | **Debug Mode Detection** | Checks if debug mode is enabled in production | 🟡 Medium |
| 13 | **Insecure Protocol Detection** | Checks for insecure protocols like HTTP in connection strings | 🟡 Medium |
| 14 | **Default Credential Detection** | Checks for framework default credentials | 🔴 High |
| 15 | **Key Rotation Policy** | Evaluates the completeness of key rotation policies | 🟢 Low |

---

### 📦 Advanced Usage

#### Multi-environment Management

```bash
# Initialize multi-environment configuration
envshield init --envs dev,staging,prod

# Set variables for different environments
envshield set DATABASE_URL "postgres://localhost/dev" --env dev
envshield set DATABASE_URL "postgres://staging-db/app" --env staging
envshield set DATABASE_URL "postgres://prod-db/app" --env prod

# Switch environment
envshield switch prod
```

#### Runtime Decryption Injection

```bash
# Start a Python app with runtime injection
envshield run -- python app.py

# Start a Node.js app with runtime injection
envshield run -- node server.js

# Run any command with runtime injection
envshield run -- make deploy
```

How runtime injection works:
1. Reads the `.env.vault` encrypted file
2. Decrypts it in process memory
3. Injects the decrypted variables into the child process environment
4. Decrypted data exists only in memory and is automatically cleared when the process exits

#### CI/CD Integration

```yaml
# GitHub Actions example
- name: Setup EnvShield
  run: pip install envshield

- name: Decrypt environment
  run: envshield decrypt .env.vault --output .env
  env:
    ENVSHIELD_MASTER_KEY: ${{ secrets.ENVSHIELD_MASTER_KEY }}

- name: Run security audit
  run: envshield audit .env --format json --output audit-report.json

- name: Scan source code
  run: envshield scan ./src --exclude node_modules,venv
```

```yaml
# GitLab CI example
security_audit:
  stage: test
  before_script:
    - pip install envshield
  script:
    - envshield decrypt .env.vault --output .env
    - envshield audit .env
    - envshield scan ./src
  artifacts:
    reports:
      security_audit: audit-report.json
```

#### Export & Import

```bash
# Export as JSON format
envshield export --format json --output config.json

# Export as YAML format
envshield export --format yaml --output config.yaml

# Import from JSON
envshield import config.json

# Import from YAML
envshield import config.yaml
```

---

### 🤝 Contributing

We welcome and appreciate every contributor! Before participating, please read the following guidelines:

#### Submitting a Pull Request

1. **Fork** this repository and create your feature branch: `git checkout -b feature/amazing-feature`
2. **Write code** and ensure all tests pass: `pytest tests/`
3. **Commit changes** following the [Conventional Commits](https://www.conventionalcommits.org/) specification: `git commit -m 'feat: add amazing feature'`
4. **Push** to your fork: `git push origin feature/amazing-feature`
5. Open a **Pull Request** with a detailed description of your changes

#### Submitting an Issue

- Use a clear and descriptive title
- Include steps to reproduce and expected behavior
- Include your runtime environment (OS, Python version, EnvShield version)
- Attach error log screenshots when possible

#### Code Standards

- Follow PEP 8 coding conventions
- All public functions must include docstrings
- New features must include corresponding unit tests
- Security-related code changes require additional code review

---

### 📄 License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

```
MIT License

Copyright (c) 2024 EnvShield Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
