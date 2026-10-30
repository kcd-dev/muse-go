// Example: supply an existing account password and call the protocol library.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/kcd-dev/muse-go/login"
	"github.com/kcd-dev/muse-go/muse"
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
		Email: os.Getenv("MUSE_EMAIL"), Password: os.Getenv("MUSE_PASSWORD"),
		Proxy: os.Getenv("MUSE_PROXY"),
	})
	if err != nil {
		return err
	}
	client := muse.NewClient(muse.Config{})
	defer client.Close()
	account := &muse.Account{
		ID: "example", Cookies: result.Cookies, CookieExpires: result.CookieExpires,
		Proxy: os.Getenv("MUSE_PROXY"),
	}
	_, err = client.Chat(ctx, account, "你好", nil, func(delta string) { fmt.Print(delta) })
	fmt.Println()
	return err
}
