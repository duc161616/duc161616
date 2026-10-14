package server

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Autumn-27/artex/selfupdate"
)

// releaseCache 是保护 GitHub 配额的那一层：未认证的 API 只有 60 次/小时/IP，
// 而顶栏的"有新版本"提示每次整页加载都会查一次。缓存一旦失效，用户多开几个
// 标签页就会把配额耗光，之后真想更新反而查不动。

func newTestCache(fetch func(context.Context, *http.Client) (*selfupdate.Release, error)) *releaseCache {
	return &releaseCache{fetch: fetch}
}

func TestReleaseCacheServesFromCache(t *testing.T) {
	calls := 0
	c := newTestCache(func(context.Context, *http.Client) (*selfupdate.Release, error) {
		calls++
		return &selfupdate.Release{TagName: "v0.3.8"}, nil
	})

	for range 5 {
		rel, err := c.get(t.Context(), nil, false)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if rel.TagName != "v0.3.8" {
			t.Fatalf("TagName = %q", rel.TagName)
		}
	}
	if calls != 1 {
		t.Errorf("5 queries should hit the source only once, actually %d", calls)
	}
}

func TestReleaseCacheForceBypasses(t *testing.T) {
	calls := 0
	c := newTestCache(func(context.Context, *http.Client) (*selfupdate.Release, error) {
		calls++
		return &selfupdate.Release{TagName: "v0.3.8"}, nil
	})

	if _, err := c.get(t.Context(), nil, false); err != nil {
		t.Fatal(err)
	}
	// 用户点「检查更新」必须拿到实时结果，否则刚发布的版本要等缓存过期才看得见。
	if _, err := c.get(t.Context(), nil, true); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("force should bypass the cache, want 2 source hits, actually %d", calls)
	}
}

func TestReleaseCacheExpiresAfterTTL(t *testing.T) {
	calls := 0
	c := newTestCache(func(context.Context, *http.Client) (*selfupdate.Release, error) {
		calls++
		return &selfupdate.Release{TagName: "v0.3.8"}, nil
	})

	if _, err := c.get(t.Context(), nil, false); err != nil {
		t.Fatal(err)
	}
	// 把落库时间往前拨到刚过期，模拟 TTL 到点。
	c.at = time.Now().Add(-releaseTTL - time.Second)
	if _, err := c.get(t.Context(), nil, false); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("after the TTL expires it should hit the source again, want 2, actually %d", calls)
	}
}

func TestReleaseCacheUsesShorterTTLForErrors(t *testing.T) {
	calls := 0
	c := newTestCache(func(context.Context, *http.Client) (*selfupdate.Release, error) {
		calls++
		return nil, errors.New("github unreachable")
	})

	if _, err := c.get(t.Context(), nil, false); err == nil {
		t.Fatal("want an error")
	}
	// 失败结果也要缓存一会儿，否则 GitHub 不可达时每次页面加载都白等一次超时。
	if _, err := c.get(t.Context(), nil, false); err == nil {
		t.Fatal("want an error")
	}
	if calls != 1 {
		t.Errorf("errors should be cached briefly, want 1 source hit, actually %d", calls)
	}

	// 但错误的 TTL 必须明显短于成功的，网络恢复后要能很快自愈。
	if releaseErrTTL >= releaseTTL {
		t.Fatalf("error TTL (%v) must be shorter than the success TTL (%v)", releaseErrTTL, releaseTTL)
	}
	c.at = time.Now().Add(-releaseErrTTL - time.Second)
	if _, err := c.get(t.Context(), nil, false); err == nil {
		t.Fatal("want an error")
	}
	if calls != 2 {
		t.Errorf("after the error TTL expires it should retry, want 2, actually %d", calls)
	}
}

func TestReleaseCacheDoesNotPoisonOnCallerCancel(t *testing.T) {
	good := &selfupdate.Release{TagName: "v0.3.8"}
	c := newTestCache(func(ctx context.Context, _ *http.Client) (*selfupdate.Release, error) {
		return good, nil
	})
	if _, err := c.get(t.Context(), nil, false); err != nil {
		t.Fatal(err)
	}

	// 访客关掉标签页会取消请求。那不代表 GitHub 有问题，绝不能把"已取消"
	// 写进缓存——否则接下来 30 分钟内每个访客都会收到一条莫名其妙的错误。
	c.fetch = func(ctx context.Context, _ *http.Client) (*selfupdate.Release, error) {
		return nil, ctx.Err()
	}
	c.at = time.Now().Add(-releaseTTL - time.Second) // 让缓存过期，逼它回源

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.get(ctx, nil, false); err == nil {
		t.Fatal("when the caller has canceled, the error should be passed through to it")
	}

	// 关键不变量：被取消的那一次不留下任何痕迹——缓存里既没有"已取消"这个错误，
	// 也还保着上一次的好结果。
	if c.err != nil {
		t.Fatalf("cancellation errors should not be cached, got %v", c.err)
	}
	if c.rel == nil || c.rel.TagName != "v0.3.8" {
		t.Fatalf("the cache should keep the last good result, got %+v", c.rel)
	}

	// 那次取消没换来任何新数据，所以下一个访客理应重新回源——而且能正常拿到结果，
	// 不会被上一次的取消连累。
	c.fetch = func(context.Context, *http.Client) (*selfupdate.Release, error) {
		return good, nil
	}
	rel, err := c.get(t.Context(), nil, false)
	if err != nil {
		t.Fatalf("a normal request after cancellation should not error: %v", err)
	}
	if rel == nil || rel.TagName != "v0.3.8" {
		t.Fatalf("should get the normal result, got %+v", rel)
	}
}
