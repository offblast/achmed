package cache

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/embed"
	"github.com/coreos/pkg/capnslog"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/net/context"
)

var (
	tkey   = "test"
	tvalue = []byte("foo")
)

func testcache(t *testing.T, c autocert.Cache) {
	ctx := context.Background()
	_, err := c.Get(ctx, tkey)
	if err == nil {
		t.Fatalf("expected error, got %q", err)
	}

	if err := c.Put(ctx, tkey, tvalue); err != nil {
		t.Fatalf("expected nil errpr. got %q", err)
	}

	b, err := c.Get(ctx, tkey)
	if err != nil {
		t.Fatalf("expected nil error, got %q", err)
	}

	if !bytes.Equal(b, tvalue) {
		t.Fatalf("expected key %q, got %q", tvalue, b)
	}

	if err := c.Delete(ctx, tkey); err != nil {
		t.Fatalf("expected nil error, got %q", err)
	}
}

func TestMemCache(t *testing.T) {
	cache := NewMemCache()
	testcache(t, cache)
}

func init() {
	// shutup etcd
	capnslog.MustRepoLogger("github.com/coreos/etcd").SetRepoLogLevel(capnslog.ERROR)
	capnslog.MustRepoLogger("github.com/coreos/etcd/etcdserver").SetRepoLogLevel(capnslog.ERROR)

	// fixup listener
	embed.DefaultListenPeerURLs = "http://127.0.0.2:2380"
	embed.DefaultListenClientURLs = "http://127.0.0.2:2379"
	embed.DefaultInitialAdvertisePeerURLs = "http://127.0.0.2:2380"
	embed.DefaultAdvertiseClientURLs = "http://127.0.0.2:2379"
}

func getEtcd(tb testing.TB) (*embed.Etcd, func()) {
	cfg := embed.NewConfig()

	dir, err := ioutil.TempDir("", "achmed-cache")
	if err != nil {
		tb.Fatal(err)
	}
	cfg.Dir = dir
	e, err := embed.StartEtcd(cfg)
	if err != nil {
		tb.Fatal(err)
	}
	closer := func() {
		e.Close()
		os.RemoveAll(dir)
	}

	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(60 * time.Second):
		e.Server.Stop() // trigger a shutdown
		tb.Fatal("etcd server took too long to start!")
	}

	return e, closer
}

func TestEtcdCache(t *testing.T) {
	etcd, cancel := getEtcd(t)
	defer cancel()

	url := fmt.Sprintf("http://%s", etcd.Clients[0].Addr())
	etcdClient, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{url},
		DialTimeout: 5 * time.Second,
	})

	if err != nil {
		t.Fatal(err)
	}

	etcdcache := &EtcdCache{
		Client: etcdClient,
	}

	testcache(t, etcdcache)

	cryptpubkey, err := openpgp.ReadArmoredKeyRing(strings.NewReader(cryptpubtext))
	if err != nil {
		t.Fatal(err)
	}

	cryptseckey, err := openpgp.ReadArmoredKeyRing(strings.NewReader(cryptsectext))
	if err != nil {
		t.Fatal(err)
	}

	cryptcache := &CryptCache{
		Plaintext: etcdcache,
		Encrypt:   cryptpubkey,
		Decrypt:   cryptseckey,
	}

	testcache(t, cryptcache)
}

func TestCryptCache(t *testing.T) {
	memcache := NewMemCache()

	cryptpubkey, err := openpgp.ReadArmoredKeyRing(strings.NewReader(cryptpubtext))
	if err != nil {
		t.Fatal(err)
	}

	cryptseckey, err := openpgp.ReadArmoredKeyRing(strings.NewReader(cryptsectext))
	if err != nil {
		t.Fatal(err)
	}

	cryptcache := &CryptCache{
		Plaintext: memcache,
		Encrypt:   cryptpubkey,
		Decrypt:   cryptseckey,
	}

	testcache(t, cryptcache)
}

const cryptpubtext = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mQENBFfoWzsBCADMmetqHesaN0iRKDZbqmdpK+PpSCdl6HYbBC624W/jYj0CCMIH
0Wt1FyL5zuRF0fvJKjvzWOynpbVdb9xcvZiAuxzv/Gl8o4LLC7sPW8EZ/hbpMJtN
ZPq1nObKvEPyReMjNxz5xPSIEYyzARViPRKMfq2Tr+XVfwNSH4yiAulP9TCAOcVF
qghG/B9i/34fLQwmhx6EWC3B/cxAeY7mLQJsu8UOojNCJRYLQKmBrYG6UcelksID
qqMVBfQAvAqyEe4CZnYMpSsZjWMMuiCaz7jH863Sj40wQtEsKWpQ596yOs7CEIek
Wxdbt9HL+j9gRXKBKXKvJiMy8gADpBYS7SHNABEBAAG0HlRlc3QgKHRlc3QpIDx0
ZXN0QGV4YW1wbGUuY29tPokBOQQTAQgAIwUCV+hbOwIbAwcLCQgHAwIBBhUIAgkK
CwQWAgMBAh4BAheAAAoJEC9zQlp62KbAGCMIALuQkznCXWQ4iYa0zeil94HaiszU
ZN2LrlXEsSiMAitdciNe50teM44mOOIEdtik4O0ALeq39nxIWRWEetmh3AL9ADxK
Owyo4djtFvqYWHLBq0rtRGKT/hp0iLB5fhgTGjzrHMiYAuzUAMLUfe16fZiyKo9W
+b+lrotIELxRIK9pw7E7osKiwQpsTKucIBK5kUbUVWOyuSvteRv8Jw12TKRNPLgE
SmG//qvTeuEZAplvpb51lKkepGSSYrYTUX0Poiwlb3xL/A78S5pgEVazI8ndAeb9
ImFzD4d30KiUbTvR8bg1svon+jfpB+Wkp5mM91AAKiBeJulfZhLtY8Yjnve5AQ0E
V+hbOwEIAKLUl4ey4lVpbRvyPB+9MDgE+KqCdDVx4ru+m9mbxg/za0bcNpM304IL
jGYO/UZPOAqhEXXtI3dYsh/qqBR8IL3xVBfKIDf9rWqY0SJZghKCBR2ZTxK2RVND
kl4fxB/gSia/DI3vBb0hB7DeC6uH1SMYMOWR8sTKM99/grN5WhKYA/Qhd6BQxjQm
wc79G/7PxyANnF64lyRzTSk7CE+OCf/xIU/JUJg8N0ZnPKEzHKkSRejwjHzQqWea
VhDLqSi0CaLl2qEXLQns1vC6+X2E/y1sP0uBkURlxJxFGv3ASr6D0kw6xcaekmQ9
DSCdqb9fhT3ud/U3Uf1jcJjbH9zeY6sAEQEAAYkBHwQYAQgACQUCV+hbOwIbDAAK
CRAvc0JaetimwP/qCACSJ2ytMiHh+moX/7OHcwcAqy81zrVtOYVG4+eukZTWK98c
YPSP1GLdv7EUCKBd9BDebBXFXXdlnKPjjyTqt+7CU/quKkJLrQjw5wH/Ps4/6U2n
eOoZmLDi1XvBlpGZxKRdDElWYZEZhmrcxMwiZwAQWmn7LD7djXVm+zzWRrY+BHCk
sJRIE2rbPH2kZXPLi4YrvgeOeMIk0YUVCr5Sj45W2oseECSvkU4eZ6zY711lGfk5
N+mAeyhAi0eOJmCKrgWW1d+bHMaf4bjNPTr5f4WXriz9c8pcwi4tYh/n1iiOKbcN
olPMTzcjhj7LywKWfHMQg9l+OAYSRCvbY/Sg3ToZ
=1a8q
-----END PGP PUBLIC KEY BLOCK-----
`

const cryptsectext = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v2

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
=Sq5J
-----END PGP PRIVATE KEY BLOCK-----
`
