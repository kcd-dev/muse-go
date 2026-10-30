# 写代码说明

本文给两类人：把 Muse 登录、对话和媒体生成嵌进自己的 Go 服务的人；修改协议库本身的人。字段、超时、错误分类和禁止事项都以当前实现为准。协议字节布局见实现仓库的 `docs/protocol.md`，本文不重复握手字段表。

模块：

```text
github.com/CoolkHz/muse-protocol-go/login
github.com/CoolkHz/muse-protocol-go/muse
github.com/CoolkHz/muse-protocol-go/hatch
```

Go 1.24+。`go get github.com/CoolkHz/muse-protocol-go`。

## 写之前先定边界

库保证：

- 一次 `login.Login` 使用独立 Cookie jar，成功后只把 Muse 源站适用的 Cookie 放进 `login.Result`。
- 密码和验证码只参与这一次登录。`Password`、`GetOTP`、`Cookies`、`AuthToken`、`NotaryToken`、代理字符串不参与 JSON 序列化。
- `muse.NewClient` 返回的 `*muse.ProtoEngine` 按 `Account.ID` 复用引导状态和加密连接；空闲回收由调用方启动 `Janitor`。
- 每次 `Chat` / `Generate` 使用新的上游 `session_id`。文本以 `/chat/history` 为准，流事件只用来提前唤醒轮询。
- 面向调用方的错误字符串不含上游响应正文。

库不保证：

- 不注册账号，不读邮箱，不接短信，不完成年龄确认、授权同意或额外验证。遇到这类门会停，并返回需要人工处理的错误。
- 不保存密码、验证码、Cookie。长期运行的存储、访问控制和账号快照同步由调用方做。
- 不自动重试整次对话或生成。`Retryable` 只是分类。
- 取消本地等待不表示上游已经停止生成或停止计费。
- `GenRequest.N` 只限制最多返回几个已下载文件，不是上游原生张数参数。尺寸和时长以落盘文件为准。
- 不支持需要 RV 密钥认证的机密 VM，也不验证硬件远程证明。
- 真实上游是否可用，取决于账号、网络和协议版本。测试只覆盖本地模拟网关和公开 Noise 向量。

调用方必须自己做的事：提供凭据、给每个账号稳定唯一的 `ID`、在 Cookie 轮换后换一份新快照、给每次调用传可取消的 `context`、决定审批策略、决定哪些错误可以重放。

## 调用链

```text
┌──────────────────────────┐
│ 你的服务                  │
│ 凭据、账号池、存储、重试   │
└────────────┬─────────────┘
             │ 1. login.Login
             │    Password 或 GetOTP，二者互斥
             ▼
┌──────────────────────────┐
│ login                    │
│ 新 Cookie jar            │
│ 密码加密或验证码确认      │
└────────────┬─────────────┘
             │ 2. Result.Cookies → muse.Account
             ▼
┌──────────────────────────┐
│ muse.ProtoEngine         │
│ 按 Account.ID 复用连接    │
└────────────┬─────────────┘
             │ 3. GET /api/session
             │ 4. 需要时 POST /api/hatch/vm/wake
             │ 5. POST /api/hatch/token
             ▼
┌──────────────────────────┐
│ hatch.Conn               │
│ WebSocket + Noise XX     │
│ 按 stream_id 复用 RPC     │
└────────────┬─────────────┘
             │ 6. POST /chat/stream
             │ 7. 轮询 /chat/history
             │ 8. 媒体走 /media/raw/ 或 /fs/raw/
             ▼
┌──────────────────────────┐
│ ChatResult 或 []Media    │
│ 媒体文件在 DataDir/media  │
└──────────────────────────┘
```

三条写代码时最容易写错的分支：

```text
登录
  ├─ 同时给了 Password 和 GetOTP → ValidateOptions 直接失败，不发请求
  ├─ 两个都没给 → 同样在发请求前失败
  ├─ 密码分支 → 可能触发上游发信，但不会读码、不会提交 OTP、不会自动改走验证码
  └─ 验证码分支 → 只在上游接受发码之后调用 GetOTP；回调必须响应 ctx

对话 / 生成
  ├─ prompt 空白、参考图超限、Kind 不是 image/video → 连接前返回 KindBadRequest
  ├─ 连接或历史读取失败，且请求可能已送达 → 可能包一层 NoRetry
  └─ 生成只有文本、没有媒体 → KindRefusal，不要当临时错误重放

Cookie
  ├─ Account 在调用期间不可变
  └─ SetHooks 拿到新 Cookie 后，下一次调用传入新快照
```

## 包怎么选

| 你要写的代码 | 用哪个包 | 不要用 |
| --- | --- | --- |
| 业务服务、任务、API | `login` + `muse` | 不要自己拼登录 POST |
| 已有 `hatch_sess`，只续会话 | `muse.ParseCookies` + `muse.RenewSession` | 不要把 Cookie 写进日志 |
| 自定义 VM RPC | `hatch.Connect` / `Do` / `OpenContext` | 不要绕过 Noise 直接发明文 WebSocket 业务体 |
| 测试 | `internal/fakemuse` 只在库内测试使用 | 调用方不要 import `internal` |

`internal/netproxy`、`internal/wsock`、`internal/fakemuse` 不是稳定 API。

## 最小程序

下面这段是完整程序，不是片段。密码来自环境变量，成功后只留在本进程。

```go
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/CoolkHz/muse-protocol-go/login"
	"github.com/CoolkHz/muse-protocol-go/muse"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	result, err := login.Login(ctx, login.Options{
		Email:    os.Getenv("MUSE_EMAIL"),
		Password: os.Getenv("MUSE_PASSWORD"),
		Proxy:    os.Getenv("MUSE_PROXY"),
	})
	if err != nil {
		return err
	}

	client := muse.NewClient(muse.Config{DataDir: "data"})
	defer client.Close()

	account := &muse.Account{
		ID:            "account-1",
		Cookies:       result.Cookies,
		CookieExpires: result.CookieExpires,
		Proxy:         os.Getenv("MUSE_PROXY"),
	}
	reply, err := client.Chat(ctx, account, "你好", nil, func(delta string) {
		fmt.Print(delta)
	})
	if err != nil {
		return err
	}
	fmt.Printf("\n媒体文件：%d\n", len(reply.Media))
	return nil
}
```

`Account.ID` 必须稳定且唯一。两个真实账号共用一个 ID，连接和 Cookie 会串。同一个账号每次请求换一个 ID，就失去连接复用，并且 Cookie 轮换对不上。

## 登录

`login.Options` 一次登录用一份。`Password` 与 `GetOTP` 互斥。密码按字节保留，包括首尾空格，不要 `TrimSpace`。邮箱会去掉首尾空白并转小写；格式不合法时 `NormalizeEmail` 在发请求前失败。

`Timeout == 0` 时登录时限是 4 分钟。自己传的话必须在 0 到 15 分钟之间，含 0 的“使用默认”和正数上限。外层 `context` 更短时，以先到期的为准。

`SiteURL` 为空则用 `https://muse.ai`。HTTP 只允许 `localhost` 或回环地址，给测试用。URL 不能带 userinfo、query、fragment 或 path。

`Proxy` 空字符串表示继承环境代理。`direct` 表示直连。非法代理在发请求前失败。

`OnStage` 只收到固定阶段名，不会收到密码、验证码或上游正文。当前实现会发出的名字：

- `initializing`
- `checking_account`
- `encrypting_password`
- `confirming_password`
- `sending_otp`
- `waiting_otp`
- `confirming`
- `verifying`
- `completed`
- `manual_intervention`

不要把这些字符串当稳定的业务状态机去持久化。它们是进度标识。用 `login.Error` 的 `Stage` 和 `Code` 做失败分支。

### 验证码回调

`GetOTP` 只在上游接受发码请求之后调用。`sentAt` 是这次发码时刻，用来对上你自己的收件记录，不是验证码本身。

回调必须：

- 监听 `ctx.Done()`，取消时返回 `ctx.Err()`。
- 返回 4 到 16 位数字。库用 `^[0-9]{4,16}$` 校验。
- 不打印验证码，不把验证码写进结构化日志。

终端读取要放到单独 goroutine，再用 `select` 接 context。阻塞在 `ReadString` 上会让取消失效，登录会一直占着这次调用。

```go
func readOTP(ctx context.Context, sentAt time.Time) (string, error) {
	_ = sentAt
	type answer struct {
		code string
		err  error
	}
	ch := make(chan answer, 1)
	go func() {
		var code string
		_, err := fmt.Fscan(os.Stdin, &code)
		ch <- answer{code, err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case a := <-ch:
		return strings.TrimSpace(a.code), a.err
	}
}
```

回调返回错误或 context 取消后，库不会再提交 `confirm-otp`。不要在回调失败后再手动补一次确认请求。

### 密码分支

密码分支也会打账号初始化接口，上游可能因此发信。这不是验证码登录。不要在密码流程里读邮件、不要在失败后自动改走 `GetOTP`。账号当前未开放密码登录时，错误文本会要求改用邮箱验证码；那是给调用方看的结果，不是库内回退。

密码封装格式是 `#PWD_BROWSER:5:<unix>:<base64>`。每次尝试新建 AES 密钥。不要自己复用 key 或 nonce。实现细节在 `login/password.go`，调用方不需要再包一层。

### 登录结果

成功条件是会话已分配 VM，并且拿到 `hatch_sess`。响应里如果有可核验身份，必须和请求邮箱一致。

```go
if missing := muse.MissingCookies(result.Cookies); len(missing) != 0 {
    return fmt.Errorf("登录结果缺少 %v", missing)
}
```

`login.Error` 的 `Error()` 只含阶段、固定 code 或 HTTP 状态。`Unwrap()` 可能带诊断。公开日志只打 `Error()`。不要 `%+v` 整个 error，也不要记录 `Result`。

人工介入用 `errors.Is(err, login.ErrManualIntervention)`。这时停下来交给人，不要重试同一套自动化。

## 账号快照和连接

`muse.Account` 是调用方拥有的不可变快照。

```go
type Account struct {
    ID            string
    Label         string
    Cookies       map[string]string // json:"-"
    CookieExpires map[string]int64  // json:"-"
    Proxy         string            // json:"-"；空则用 Config.Proxy；direct 为直连
}
```

调用进行中不要改这份 map，也不要改调用方和库共用的同一张 map。库内部会拷贝 Cookie 再发请求，但 hook 返回后你必须用新快照发起下一次调用。

```go
var mu sync.Mutex
snapshots := map[string]*muse.Account{}

client.SetHooks(
    func(id string, cookies map[string]string, expires map[string]int64) {
        mu.Lock()
        defer mu.Unlock()
        prev := snapshots[id]
        if prev == nil {
            return
        }
        next := *prev
        next.Cookies = cookies
        next.CookieExpires = expires
        snapshots[id] = &next
        // 这里只更新你自己的存储。不要在 hook 里再调用 Chat。
    },
    func(id string, info *muse.SessionInfo) {
        // info.Cookies 同样不进 JSON。只记录 OK、VMState 这类非秘密字段。
    },
)
```

`SetHooks` 必须在并发请求开始前调用。hook 里禁止再进入 `Chat`、`Generate`、`Diagnose`，否则和连接锁交叉。hook 只负责把新快照交回你的存储。

一个进程复用一个 `ProtoEngine`。退出时 `Close()`。长期运行：

```go
go client.Janitor(ctx)
```

`Janitor` 跟随传入的 context 结束。默认空闲关闭时间是 10 分钟，可用 `Config.IdleClose` 改。需要立刻丢掉某个账号的连接时用 `Drop(id)`，不要自己关底层 WebSocket 还把账号留在引擎里。

`IsWarm(id)` 和 `WarmCount()` 只表示当前有没有活着的加密连接，不表示账号额度或登录仍然有效。

已有 Cookie、不想再登录时：

```go
cookies := muse.ParseCookies(os.Getenv("MUSE_COOKIE"))
if len(muse.MissingCookies(cookies)) != 0 {
    return errors.New("MUSE_COOKIE 必须包含 hatch_sess")
}
info, err := muse.RenewSession(ctx, "", cookies, proxy, true)
```

`ParseCookies` 接受 `a=1; b=2`、JSON 对象、带 `cookies` 字段的对象、浏览器导出的 JSON 数组，以及一行一个 Cookie。`RenewSession` 的 `site` 为空时用 `https://muse.ai`。`wake == true` 会尝试唤醒 VM，避免第一次对话把冷启动算进业务超时。返回的 `SessionInfo.Cookies` 可能已经包含 `Set-Cookie` 轮换结果，用它替换旧快照。

必需 Cookie 只有 `hatch_sess`。`hatch_native_auth_device`、`hatch_gw`、`hatch_vml` 可以有，但不是每个会话都会下发。

## Config

零值可用。`NewClient` 会拷贝配置并填默认值。

| 字段 | 零值含义 | 写代码时的约束 |
| --- | --- | --- |
| `SiteURL` | `https://muse.ai` | 只能是 origin。自定义地址给受信集成和本地测试 |
| `GatewayURL` | `wss://hatch.metaaivm.com/v1/noise` | 不能带 query 或 fragment。非 TLS 只允许回环 |
| `Proxy` | 继承环境代理 | 账号级 `Account.Proxy` 优先 |
| `DataDir` | `data` | 媒体实际目录是 `MediaDir()`，即 `DataDir/media` |
| `Timezone` | `UTC` | 传给对话请求，不是日志时区 |
| `ApprovalPolicy` | `deny` | 只允许 `deny`、`allow`、`off` |
| `ChatTimeout` | 3 分钟 | `Chat` 在 acquire 成功后套这层超时 |
| `GenerateTimeout` | 10 分钟 | `GenRequest.Timeout > 0` 时覆盖它 |
| `IdleClose` | 10 分钟 | 给 `Janitor` 用 |

发请求前可以先 `cfg.Validate()`。它只检查端点语法和审批策略，不访问上游。

审批：

- `deny`：只自动拒绝当前会话里的待决审批。这是默认值，适合不准备让模型动外部工具的服务。
- `off`：库不处理审批。未决审批会留在上游，生成可能因此停住。
- `allow`：选择上游给出的允许项。只有调用方明确接受这个权限时才写这个值。

不要把 `allow` 当“让请求更容易成功”的开关。

## 对话

```go
reply, err := client.Chat(ctx, account, prompt, refs, onDelta)
```

- `prompt` 去掉空白后不能为空。
- `refs` 最多 `muse.MaxRefImages`（4）。单张不超过 `MaxRefImageBytes`（10 MiB），合计不超过 `MaxRefTotalBytes`（24 MiB）。`Mime` 必须以 `image/` 开头，`Data` 不能空。
- `onDelta` 可以为 nil。非 nil 时，它收到的是相对上次的文本增量，不是累计全文。回调里不要做会卡住的 IO；历史轮询在同一条调用栈上继续。
- 返回的 `reply.Text` 是本轮最终文本。对话里附带生成的图片也会放进 `reply.Media`。取媒体失败时，文本结果仍然返回，媒体切片可能不完整。不要假设 `len(reply.Media)` 等于模型说它生成了几张。

多轮上下文不会自动续上一次 `Chat`。要把历史写进下一次的 `prompt`。不要复用上一次的上游 session 来“接着聊”，库每次都新建会话。

空回复返回临时错误。文本被识别为拒绝或额度不足时，按 `muse.KindOf` 处理，不要把正文再打一遍到日志。

## 生成图片或视频

```go
files, err := client.Generate(ctx, account, muse.GenRequest{
    Kind:   "image", // 或 "video"
    Prompt: "生成一张山间日出图片",
    N:      1,
    Refs:   []muse.RefImage{{Data: pngBytes, Mime: "image/png"}},
    OnProgress: func(percent int) {
        // 10 连接已取得，80 开始下载，100 下载完成。不是上游真实百分比。
    },
})
```

`Kind` 只能是 `image` 或 `video`。`N < 1` 会当成 1。上游给出的文件多于 `N` 时，保留列表末尾的 `N` 个。要多张图，必须在 prompt 里写数量，并检查 `len(files)`。

文件写到 `Config.MediaDir()`。库新建的目录是 `0700`，新建的文件是 `0600`。已经存在的目录权限不会被改。`Media` 里的宽高和时长来自文件本身，和 prompt 里写的尺寸可以不一致。

两种失败不要重放：

- 等到超时仍然没有新媒体，错误被 `NoRetry` 包住。请求可能已经在上游执行。
- 已经生成但一个文件都没取回来，同样是 `NoRetry`。先查磁盘和网络，再由人决定要不要新开一次生成。

模型只回了文本、没有媒体，是 `KindRefusal`。换 prompt 或换策略，不要原样重试同一请求。

`OnProgress` 只表示库内阶段。不要用它做计费或完成判定。完成判定是 `err == nil && len(files) > 0`。

## 错误和重试

用 `errors.As` / `muse.KindOf`，不要解析错误字符串。

```go
switch muse.KindOf(err) {
case muse.KindBadRequest:
    // 调用方输入错了。修参数，不要重试。
case muse.KindAuth:
    // Cookie 被拒。换登录结果，不要用旧快照再打。
case muse.KindQuota:
    // 额度不足。换账号或停止，不要立刻重试同一账号。
case muse.KindRateLimit:
    // 临时限流。等待 RetryAfterOf(err)，这不是额度耗尽。
case muse.KindRefusal:
    // 模型用文本拒绝了媒体请求。不要自动重放。
case muse.KindTransient:
    // 未知错误也归到这里。仍要先看 Retryable。
}
if !muse.Retryable(err) {
    return err
}
wait := muse.RetryAfterOf(err)
```

`KindOf` 对不是 `*muse.Error` 的错误返回 `KindTransient`。这不表示一定可以重试。`Retryable` 在两处返回 false：错误链里有 `*muse.NoRetry`，或者种类是 `KindBadRequest` / `KindRefusal`。

`RetryAfter` 来自上游 `Retry-After`，秒数或 HTTP 日期都会解析，上限 24 小时。没有这个头时返回 0，由你自己的退避决定。

库不会替你重试整次 `Chat` 或 `Generate`。你若重试，必须是一次新的调用，并接受可能产生第二次生成。登录失败里的 `manual_intervention`、身份不匹配、密码不可用，都不要自动重试。

登录错误和协议错误不是同一个类型。登录用 `*login.Error`，协议用 `*muse.Error`。不要假设 `muse.KindOf(loginErr)` 能分出认证失败；它会落到 `KindTransient`。

## 代理

优先级：`Account.Proxy`，否则 `Config.Proxy` 或 `login.Options.Proxy`，空值再看环境变量。`direct` 关闭代理。支持 HTTP、HTTPS、SOCKS5、SOCKS5H。

无效代理必须失败返回，不要静默改成直连。日志里如果必须提到代理，只记录去掉 userinfo 之后的地址。实现侧有 `internal/netproxy.Redact`，调用方不要自己打印原始代理 URL。

`login.Options.Transport` 非 nil 时，这次登录的路由由该 `RoundTripper` 负责，库不再套账号代理。这是测试和受信集成入口，生产调用保持 nil。

## 底层 RPC

只有 `muse` 的对话和生成不够用时才直接写 `hatch`。你要自己完成 HTTPS 引导，拿到 `hatch.Session`：

```go
sess := &hatch.Session{
    VMID:      vmID,
    Endpoint:  endpoint,
    AuthToken: token, // json:"-"
}
conn, err := hatch.Connect(ctx, sess, hatch.Options{
    Proxy: proxy,
})
if err != nil {
    return err
}
defer conn.Close()
```

`VMID` 和 `AuthToken` 都空不了，否则 `Connect` 在拨号前失败。`Options.URL` 为空时用默认网关。不要记录带 `auth_token` 的完整 WebSocket URL。

一元调用：

```go
resp, err := conn.Do(ctx, hatch.Request{
    Method: http.MethodGet,
    Path:   "/api/session/list",
})
```

JSON POST 用 `DoJSON`。GET 的查询参数写在 `path` 里，`params` 会被忽略。

流式调用用 `OpenContext`，读完必须 `Close`。JSON 记录用 `NextJSON`，二进制分块用 `NextChunk`。取消、reset、断连都会唤醒等待者。不要在没关闭 stream 的情况下丢掉 `*Stream`。

服务号：

- `hatch.ServiceDaemon` = 0，普通对话
- `hatch.ServiceSentinel` = 1，审批
- `hatch.ServiceVault` = 2
- `hatch.ServiceAuthd` = 3

`hatch.Response.Body` 是业务正文。库的公开错误会去掉正文，这一层不会。调用方自己决定记不记，默认不记。

握手失败是 `*hatch.HandshakeError`。出现机密 VM 的 RV challenge 时返回不支持，不要在调用方里补一套密钥认证。

## 诊断

`Diagnose` 用来看一条账号能不能走完引导和两条探测路径。它在连接失败时把错误放进返回 map 的 `error` 字段，并且返回的 error 为 nil。不要只看第二个返回值。

```go
report, err := client.Diagnose(ctx, account)
if err != nil {
    return err
}
if msg, ok := report["error"].(string); ok && msg != "" {
    return errors.New(msg)
}
```

返回里有连接耗时、是否分配 VM、是否有 notary token，以及 `/model`、`/api/session/list` 的状态码和耗时。没有响应正文。不要把这份 map 当成健康检查的唯一标准；它不检查额度，也不发一次真实对话。

## 库内改动怎么写

改实现时保持这条数据方向，不要加第四条旁路：

```text
调用方快照
  → login 或已有 Cookie
  → muse 引导（session / wake / token）
  → hatch 加密 RPC
  → 历史轮询判定完成
  → 可选的媒体下载
```

包职责：

- `login` 只做一次认证。不要在这里发对话，不要缓存账号。
- `muse` 做会话引导、轮询完成判定、媒体落盘和错误分类。
- `hatch` 做 Noise、protobuf 和流复用。不要在这里解释聊天业务。
- `cmd/muse-protocol` 和 `examples/basic` 是示例。业务规则不要只写在示例里。

完成判定已经有固定规则：历史事件按本轮锚点过滤，助手消息和工具生命周期都结束后，再等一个安静窗口。改这个规则时必须补 `muse/proto_completion_test.go` 那一类测试。不要用“流里看到一条 delta 就当完成”。

新的上游错误要进 `classifyHTTPError` 或 `classifyTurnErr`，并给调用方一个 `Kind`。不要把上游 body 拼进 `Error()`。

公开函数保持现在的注释风格：说明它保证什么、不保证什么、凭据会不会落盘。未导出函数不必为了形式补注释。新增导出类型的秘密字段加 `` `json:"-"` ``。

### 测试

默认测试不访问真实 Muse，不使用真实账号。

- 登录：用 `http.RoundTripper` 桩，断言发了哪些请求、没提交 OTP、取消后不再确认。
- 传输：Noise 用公开 cacophony 向量。RPC 用本地流，覆盖取消、reset、分块和缓冲上限。
- 业务：`internal/fakemuse` 提供站点加 `/v1/noise`。有效测试会话是 `hatch_sess=s1`。
- 隐私：`json.Marshal` 结果里不能出现密码、验证码、Cookie、token。错误字符串不能出现上游正文。

本地验收：

```sh
go test -race ./...
go vet ./...
go build ./...
```

改完成判定、Cookie 轮换或错误分类时，至少要有一条失败用例先能稳定复现，再改实现。不要只跑通 happy path。

`login.Options.Transport` 和回环 `http://127.0.0.1` 是测试入口。生产示例继续用 `https://muse.ai` 和空 Transport。

## 日志和秘密

可以记：账号 ID、阶段名、`muse.Kind`、HTTP 状态、耗时、文件名、字节数、宽高。

不可以记：密码、验证码、Cookie、`hatch_sess`、临时 token、notary token、带 query 的网关 URL、代理 userinfo、上游响应正文、`Account` 整体、`login.Result` 整体。

示例程序在读完环境变量后应 `Unsetenv`，避免子进程继承。库本身不会读 `.env`。

生成文件在本机 `DataDir/media`。这个目录按账号数据对待，不要随仓库提交，不要打进镜像的公共层。

## 写调用方时的检查清单

发请求前：

- 邮箱能通过 `login.NormalizeEmail`。
- 密码和 `GetOTP` 只存在一个。
- `GetOTP` 能在 context 取消时返回。
- `Account.ID` 稳定且唯一。
- `hatch_sess` 存在。
- `Config.Validate()` 通过，或者你接受零值默认端点。
- hook 已在并发调用前设好，并且 hook 不再进入客户端。

拿到错误后：

- 先 `Retryable`，再 `KindOf`，再 `RetryAfterOf`。
- `NoRetry` 不自动重放生成。
- `ErrManualIntervention` 停止自动化。
- 日志只有 `err.Error()`，没有 `%#v`。

拿到成功后：

- 对话用 `reply.Text`，不用拼接 delta 作为唯一结果。delta 只用于展示。
- 生成用实际 `len(files)`，不用 `N`。
- Cookie hook 里的新 map 写回存储，下一次用新快照。

## 不要写的代码

- 不要在库里加注册、收件箱、接码、账号池和任务表。那是调用方的系统。
- 不要在密码登录失败后自动改走验证码。
- 不要为了“多轮聊天”去复用上一次 `Chat` 的上游会话。把历史放进 prompt。
- 不要把 `N` 当成上游的张数参数，也不要在下载失败后自动再 `Generate` 一次。
- 不要记录完整连接 URL。query 里有认证令牌。
- 不要在默认策略不明时把 `ApprovalPolicy` 设成 `allow`。
- 不要用真实账号做 CI。CI 只跑模拟网关和公开测试向量。
