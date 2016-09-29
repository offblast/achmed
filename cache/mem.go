package cache

import (
	"sync"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/context"
)

type MemCache struct {
	m  map[string][]byte
	mu sync.RWMutex
}

func NewMemCache() *MemCache {
	return &MemCache{m: make(map[string][]byte)}
}

func (m *MemCache) Get(ctx context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, ok := m.m[key]
	if !ok {
		return nil, autocert.ErrCacheMiss
	}

	return data, nil
}

func (m *MemCache) Put(ctx context.Context, key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.m[key] = data

	return nil
}

func (m *MemCache) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.m, key)

	return nil
}
