# AI短视频脚本生成器（持续完善版）

## 功能
- 注册 / 登录 / 登出（Bearer Token，含过期时间）
- 密码加盐哈希存储
- 套餐体系与月额度（free/basic/pro）
- 脚本生成、单条重生、历史查询
- 管理员升级套餐（admin key）
- 订单创建 + webhook支付回调（HMAC签名、幂等）
- 每周发布日历
- 健康检查与基础指标 `/health` `/metrics`
- 生成接口基础限流（每用户每分钟30次）

## 运行
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## 环境变量
- `APP_ENV` 默认 `dev`
- `ADMIN_KEY` 默认 `dev-admin-key`（prod必须覆盖）
- `TOKEN_TTL_DAYS` 默认 `30`
- `BILLING_WEBHOOK_SECRET` 默认 `dev-webhook-secret`
