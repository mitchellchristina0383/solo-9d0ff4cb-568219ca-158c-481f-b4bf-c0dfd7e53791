# 熔断网关（Circuit-Breaker Gateway）

值班止损场景：上游连续出错时两台网关**共享熔断状态**自动停止转发，上游恢复后
仅放行一笔探测，探测成功再接流。FastAPI + SQLite（WAL）实现，浏览器即可操作。

## 架构

```
浏览器 ──► gateway1 (容器 8000 → 宿主 8001) ─┐
       └► gateway2 (容器 8000 → 宿主 8002) ─┴──► flaky-upstream (宿主 8000)
                  两台网关挂载同一个 Docker volume，
                  熔断状态存于 /data/breaker.db（SQLite WAL）
```

- `app/breaker.py`：熔断核心，纯标准库。所有状态迁移在 `BEGIN IMMEDIATE`
  事务内完成，跨进程串行化；WAL + `busy_timeout=10s` 支持两实例并发读写。
- `app/signed_auth.py`：`/proxy` 的 HMAC 签名校验与**跨实例共享的单次随机数记录**
  （SQLite `signed_admissions`，主键 `(client_id, nonce)`，`BEGIN IMMEDIATE`
  内插入）。纯标准库。
- `app/gateway_app.py`：网关，含 `/proxy`（签名入口）、管理 API 与内嵌网页。
- `app/upstream_app.py`：可切换 `normal` / `slow`（5 秒）/ `error`（500）的上游。
  失联场景用 `docker compose stop upstream` 真实模拟。

## 签名入口（`GET /proxy`）

值班场景下，未授权或重放的 GET 不得占用上游容量，也不得抢走唯一的恢复探测
资格。因此 `/proxy` 只有签名路径，签名校验发生在 `Breaker.dispatch()` 和任何
上游请求**之前**。

客户端持有密钥（**密钥不上行**），请求携带四个头：

```
X-Client-Id:  demo-client
X-Timestamp:  1760000000            # Unix 秒
X-Nonce:      4f3c...               # 每次请求新的随机数，可打印字符
X-Signature:  <hex(HMAC-SHA256(secret, canonical))>
```

canonical 为 UTF-8、`\n` 分隔、无结尾换行：

```
v1
<client id>
<timestamp>
<nonce>
<METHOD>
<原始路径与查询串>
```

例如普通签名 GET 为 `v1\ndemo-client\n1760000000\n4f3c...\nGET\n/proxy`。
“原始路径与查询串”取 ASGI `raw_path` + `?` + `query_string`（保留百分号编码），
与浏览器 `location.pathname + location.search` 一致；查询串也参与签名。

拒绝规则（任一命中都在**访问上游、改动熔断状态之前**返回）：

| 情况 | HTTP | `reason` |
| --- | --- | --- |
| 缺少任一签名头 | 401 | `signature_required` |
| 客户端标识/随机数格式非法 | 401 | `invalid_client_id` / `invalid_nonce` |
| 未知客户端、密钥不匹配或签名被篡改（三者同样返回） | 401 | `invalid_signature` |
| 时间戳偏离服务器超过 **30 秒**（含未来时间） | 401 | `timestamp_skew` |
| 同一客户端的随机数已被使用（含并发重放） | 409 | `replay_detected` |
| 共享受理记录不可写/打不开（只读卷、目录缺失等） | 503 | `admission_ledger_unavailable` |

受理记录与熔断状态同处一个共享 SQLite 文件（可用 `SIGNED_LEDGER_PATH` 覆盖）。
并发提交同一 `(client_id, nonce)` 时，两台网关的 `BEGIN IMMEDIATE` + 主键插入
严格串行，只有一笔成功；其余返回 409。只有**通过校验的**请求才会占用随机数：
签名错误、时间戳越界、记录不可写等拒绝既不会占用随机数，也不会产生上游调用、
熔断计数或探测占位。随机数只在受理时一次性占用（因此同一随机数的重发/重放
恒为 409，哪怕首笔最终因熔断被 503）。

时间戳窗口**只在受理时检查**：已放行的请求即使处理中超过 30 秒，仍按原熔断
规则完成并记录结果（迟到结果仍受既有的 epoch/probe_token 防护约束）。

配置：`SIGNED_CLIENTS='{"client-a":"secret-a"}'`（推荐）或
`SIGNED_CLIENT_ID` + `SIGNED_CLIENT_SECRET`（单客户端演示，默认
`demo-client` / `demo-secret-please-change`）；`SIGNED_MAX_SKEW_SECONDS`
（默认 30）、`SIGNED_NONCE_TTL_SECONDS`（默认 3600，仅清理过期行）。

## 熔断规则（与需求逐条对应）

1. **连续 3 次** 5xx 或超时（按完成顺序计数）→ `OPEN`，两台网关立即 503 拒绝，
   不再访问上游。
2. CLOSED 下任一成功响应把失败计数清零。
3. `OPEN` 冷却 **2 秒**后进入 `HALF_OPEN`，跨实例**只放行一笔恢复探测**，
   探测期间其余请求立即 503（`probe_in_flight`）。
4. 探测成功 → `CLOSED` 恢复转发；探测失败 → 重新冷却 2 秒。
5. 探测超过 3 秒无结论（超时、实例被 kill）→ 另一台实例可**回收并重新探测**。
6. **迟到结果防护**：每笔决策带 token（普通请求校验 `epoch+CLOSED`，探测校验
   `probe_token+HALF_OPEN`）；失效探测和旧请求的迟到回包一律忽略，不能改写新结论。

关键参数可经环境变量调整：`CB_FAILURE_THRESHOLD`、`CB_COOLDOWN_SECONDS`、
`CB_PROBE_TIMEOUT_SECONDS`、`UPSTREAM_TIMEOUT`。

## 启动（Docker Compose）

```bash
docker compose up --build
# 网页控制台（任选一个入口，页面内可切换入口地址）
#   http://localhost:8001/   或   http://localhost:8002/
```

页面功能：切换上游模式；发 1/3/5 笔或并发 10 笔**签名** GET；在“签名请求”
卡片填写本地演示客户端密钥（仅浏览器内计算，不随请求发送）后发起签名请求、
**重发原签名**、**并发重放 ×8**、**篡改签名**、**时间戳 -60s**；查看每笔结果、
熔断状态（状态徽章、失败计数、冷却剩余、探测属主）与两实例共享事件流。
密钥只存在于页面输入框，不读取自服务器、不写入存储、不随请求发送。

### 无 Docker 环境的本地等效启动

```bash
./scripts/run_local.sh        # 三个 uvicorn 进程，共享 ./data/breaker.db
./scripts/stop_local.sh       # 停止
```

## 自测

```bash
# 单元测试
python3 -I tests/test_breaker.py        # 状态机、并发、迟到结果、探测回收
python3 -I tests/test_signed_auth.py    # 签名/时序/重放/不可写受理记录
python3 -I tests/test_gateway_asgi.py   # 进程内 ASGI：受理先于熔断、慢请求、
                                        # 探测交错、记录不可写（需 app 依赖）

# 端到端：先起本地三进程，再执行（76 项检查，含签名受理一节）
PYTHONPATH=$PWD:$PWD/.pylibs/lib/python3.11/site-packages ./scripts/run_local.sh
python3 -I tests/test_integration.py
```

`run_local.sh` 会读取当前环境变量；若使用仓库内 `.pylibs`，启动时带上上述
`PYTHONPATH`。

## 主要 HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/proxy` | **需 HMAC 签名头**；经熔断转发到上游；未授权/重放 401/409；熔断时 503，超时 504，失联 502 |
| GET | `/api/config` | 公开的签名参数（端点、头名、版本、最大时偏、演示客户端标识；不含密钥） |
| GET | `/api/state` | 当前熔断状态（含冷却剩余、探测属主） |
| GET | `/api/events?limit=20` | 共享事件流 |
| POST | `/api/upstream/mode` | 经网关切换上游模式 `{"mode":"normal|slow|error"}` |
| GET | `/health` | 网关健康检查 |
