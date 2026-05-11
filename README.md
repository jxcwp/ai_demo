# AI短视频脚本生成器（持续完善版）

## 功能
- 注册 / 登录 / 登出（Bearer Token，含过期时间）
- 密码加盐哈希存储
- 套餐体系与月额度（free/basic/pro）
- 脚本生成、单条重生、历史查询
- 管理员升级套餐（admin key）
- 订单创建 + webhook支付回调（HMAC签名、幂等）
- 管理员用户与订单查询：`/admin/users`、`/admin/orders`（支持 `limit/offset` 分页）
- 模板库能力：`/admin/templates` 新增模板、`/templates` 按行业查询
- 收藏能力：`/favorites` 收藏并回看高质量脚本
- 每周发布日历
- 自定义发布排期：`/schedules` 创建/查询，`/schedules/{id}/status` 更新完成状态
- 数据复盘：`/analytics/summary` 查看生成、收藏、执行进度
- 内容导出：`/history/{id}/export` 支持 markdown/json 导出
- 健康检查与基础指标 `/health` `/metrics`
- 生成接口基础限流（每用户每分钟30次）

## 运行
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## 受限网络环境安装（推荐）
如果默认源安装失败（如代理 403），可使用脚本并指定镜像源：

```bash
PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple bash scripts/setup_env.sh
source .venv/bin/activate
pytest -q
```

## CI
- 已提供 GitHub Actions：`.github/workflows/python-tests.yml`，提交后自动执行 `pytest -q`。

## 环境变量
- `APP_ENV` 默认 `dev`
- `ADMIN_KEY` 默认 `dev-admin-key`（prod必须覆盖）
- `TOKEN_TTL_DAYS` 默认 `30`
- `BILLING_WEBHOOK_SECRET` 默认 `dev-webhook-secret`
