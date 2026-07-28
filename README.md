# CIVIC 生产部署说明

这套系统采用“GitHub Pages 前台与后台界面 + 腾讯 CloudBase 云托管 API + CloudBase 文档数据库”的结构，面向中国大陆访问。浏览器不会直接读写数据库，所有报名、审核和管理员操作均经过服务端 API。

## 已实现

- 实时活动与剩余名额
- 在线报名、重复提交保护、并发名额事务
- 报名编号 + 手机号状态查询
- 姓名、手机、邮箱、出生年份与经验加密存储
- 多名同权管理员
- 首位管理员安全初始化
- 新管理员首次登录强制修改密码
- 管理员账号启停与密码重置
- 报名筛选、审核、备注、CSV 导出
- 管理操作审计日志
- CORS、JWT、限流、蜜罐字段与输入校验

## 1. 创建 CloudBase 环境

在腾讯 CloudBase 控制台创建环境。中国大陆用户为主时建议选择广州地域，并开通文档型数据库与云托管。

创建以下集合：

- `activities`
- `registrations`
- `admins`
- `audit_logs`

数据库不要开放浏览器端直接读写；前后端只通过云托管 API 通信。

建议创建以下索引：

| 集合 | 字段 | 类型 |
| --- | --- | --- |
| `activities` | `published`, `sortOrder` | 组合索引 |
| `registrations` | `reference` | 唯一索引 |
| `registrations` | `requestId` | 唯一索引 |
| `registrations` | `activityId`, `createdAt` | 组合索引 |
| `registrations` | `activityId`, `status`, `createdAt` | 组合索引 |
| `registrations` | `reference`, `phoneHash` | 组合索引 |
| `admins` | `email` | 唯一索引 |
| `audit_logs` | `createdAt` | 普通索引 |

## 2. 部署 API

在 CloudBase 云托管中选择 Git 部署，连接 GitHub 仓库：

- 分支：`agent/production-backend`（首次联调）；确认后再切换 `main`
- 服务目录：`server`
- 构建方式：Dockerfile
- 服务端口：`8080`
- 健康检查：`/api/health`

设置以下生产环境变量：

```text
CLOUDBASE_ENV_ID=<CloudBase 环境 ID>
ALLOWED_ORIGINS=https://wenyao8139.github.io
JWT_SECRET=<至少 32 字符的随机值>
PII_ENCRYPTION_KEY=<64 位十六进制随机值>
PII_HASH_SECRET=<至少 32 字符的随机值>
BOOTSTRAP_TOKEN=<一次性初始化口令，至少 16 字符>
CONSENT_VERSION=2026-01
TOKEN_EXPIRES_IN=8h
NODE_ENV=production
```

可在自己的终端生成随机值，不要把结果写入仓库或发到聊天中：

```bash
openssl rand -hex 32
openssl rand -hex 32
openssl rand -hex 32
openssl rand -base64 32
```

其中 `PII_ENCRYPTION_KEY` 用于解密历史报名数据，不能随意更换；如需轮换必须先做数据迁移。更换 `JWT_SECRET` 会使现有管理员登录失效。

## 3. 连接前端

API 部署成功后，把公开 HTTPS 地址写入根目录 `config.js`：

```js
window.CIVIC_CONFIG = {
  apiBase: "https://你的云托管服务域名",
  siteName: "CIVIC 志愿服务平台",
};
```

前台地址：

```text
https://wenyao8139.github.io/volunteer-service-signup/
```

后台地址：

```text
https://wenyao8139.github.io/volunteer-service-signup/admin.html
```

## 4. 初始化管理员与活动

第一次打开后台时，选择“首次使用？初始化管理员”，输入姓名、邮箱、密码和部署时设置的 `BOOTSTRAP_TOKEN`。系统只允许初始化一次。

进入后台后：

1. 在“活动管理”创建并发布活动。
2. 在“管理员”添加其他同权管理员。
3. 新管理员使用初始密码登录后，系统会强制其设置新密码。

如需导入示例活动，可在已具备 CloudBase 服务端访问凭证的环境中执行：

```bash
cd server
CLOUDBASE_ENV_ID=<环境 ID> npm run seed
```

## 5. 上线前检查

- 提供真实的运营主体名称、联系邮箱或电话、隐私请求渠道。
- 补充正式隐私政策、数据保存期限和删除流程。
- 使用两个不同管理员账号完成登录、审核、导出和密码重置测试。
- 用同一手机号重复报名同一活动，确认系统阻止重复记录。
- 将活动名额设为 1，并发提交两次，确认只生成一条有效报名。
- 在 CloudBase 控制台确认数据库每日备份与回档能力可用。
- 不在截图、工单、聊天或代码仓库中暴露报名者数据与任何密钥。
