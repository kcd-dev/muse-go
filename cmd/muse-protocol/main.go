// muse-protocol demonstrates caller-supplied authentication and protocol calls.
// It keeps the authenticated session in memory for this process only.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/kcd-dev/muse-go/login"
	"github.com/kcd-dev/muse-go/muse"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "失败:", err)
		os.Exit(1)
	}
}

func run() error {
	auth := flag.String("auth", "otp", "otp, password, or cookie (caller supplies credentials)")
	mode := flag.String("mode", "chat", "login, chat, image, or video")
	prompt := flag.String("prompt", "", "text to send to Muse")
	dataDir := flag.String("output", "data", "generated media is saved under this directory's media/ subdirectory")
	flag.Parse()
	if *mode != "login" && *mode != "chat" && *mode != "image" && *mode != "video" {
		return errors.New("mode 必须是 login、chat、image 或 video")
	}
	if *mode != "login" && strings.TrimSpace(*prompt) == "" {
		return errors.New("请使用 --prompt 提供提示词")
	}
	if *auth != "otp" && *auth != "password" && *auth != "cookie" {
		return errors.New("auth 必须是 otp、password 或 cookie")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	proxy := os.Getenv("MUSE_PROXY")
	account := &muse.Account{ID: "demo", Proxy: proxy}
	if *auth == "cookie" {
		account.Cookies = muse.ParseCookies(os.Getenv("MUSE_COOKIE"))
		_ = os.Unsetenv("MUSE_COOKIE")
		if len(muse.MissingCookies(account.Cookies)) != 0 {
			return errors.New("MUSE_COOKIE 必须包含 hatch_sess")
		}
		if *mode == "login" {
			info, err := muse.RenewSession(ctx, "https://muse.ai", account.Cookies, proxy, false)
			if err != nil {
				return err
			}
			if !info.OK {
				return errors.New("会话尚未就绪")
			}
		}
	} else {
		options := login.Options{
			Email: os.Getenv("MUSE_EMAIL"), Proxy: proxy,
			OnStage: func(stage string) { fmt.Fprintln(os.Stderr, "登录阶段:", stage) },
		}
		if *auth == "password" {
			options.Password = os.Getenv("MUSE_PASSWORD")
			_ = os.Unsetenv("MUSE_PASSWORD")
			if options.Password == "" {
				return errors.New("请通过 MUSE_PASSWORD 提供已有账号密码")
			}
		} else {
			options.GetOTP = readOTP
		}
		result, err := login.Login(ctx, options)
		options.Password = ""
		if err != nil {
			return err
		}
		account.Cookies, account.CookieExpires = result.Cookies, result.CookieExpires
	}
	fmt.Fprintln(os.Stderr, "登录成功；会话仅保存在本进程内。")
	if *mode == "login" {
		return nil
	}
	client := muse.NewClient(muse.Config{DataDir: *dataDir, Proxy: proxy})
	defer client.Close()
	if *mode == "chat" {
		_, err := client.Chat(ctx, account, *prompt, nil, func(delta string) { fmt.Print(delta) })
		fmt.Println()
		return err
	}
	media, err := client.Generate(ctx, account, muse.GenRequest{Kind: *mode, Prompt: *prompt, N: 1})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(media)
}

// readOTP is a caller-side example, not a mailbox or SMS integration. The
// protocol invokes it only after the upstream has accepted the OTP request.
func readOTP(ctx context.Context, _ time.Time) (string, error) {
	fmt.Fprint(os.Stderr, "请输入自行获取的验证码: ")
	type answer struct {
		code string
		err  error
	}
	result := make(chan answer, 1)
	go func() {
		code, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if errors.Is(err, io.EOF) && strings.TrimSpace(code) != "" {
			err = nil
		}
		result <- answer{code, err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case a := <-result:
		return strings.TrimSpace(a.code), a.err
	}
}
