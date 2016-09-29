package cache

import (
	"path"

	"github.com/coreos/etcd/clientv3"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/context"
)

const etcdPrefix = "offblast.org/achmed"

func mkkey(s ...string) string {
	s = append([]string{etcdPrefix}, s...)
	return path.Join(s...)
}

// EtcdCache implements autocert.Cache with etcd v3 protocol.
type EtcdCache struct {
	Client *clientv3.Client
}

func (e *EtcdCache) Get(ctx context.Context, key string) ([]byte, error) {
	k := mkkey("cache", key)
	r, err := e.Client.Get(ctx, k)
	if err != nil {
		return nil, err
	}

	if len(r.Kvs) == 0 {
		return nil, autocert.ErrCacheMiss
	}

	return r.Kvs[0].Value, nil
}

func (e *EtcdCache) Put(ctx context.Context, key string, data []byte) error {
	k := mkkey("cache", key)
	_, err := e.Client.Put(ctx, k, string(data))
	return err
}

func (e *EtcdCache) Delete(ctx context.Context, key string) error {
	k := mkkey("cache", key)
	_, err := e.Client.Delete(ctx, k)
	return err
}
