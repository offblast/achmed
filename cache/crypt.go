package cache

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/net/context"
)

var (
	noDecrypt = errors.New("unable to do decryption")
	noEncrypt = errors.New("unable to do encryption")
)

type CryptCache struct {
	Plaintext autocert.Cache

	// OpenPGP Encryption key pubring
	Encrypt openpgp.EntityList

	// OpenPGP Decryption key secring
	Decrypt openpgp.EntityList
}

func (c *CryptCache) Get(ctx context.Context, key string) ([]byte, error) {
	if c.Decrypt == nil {
		return nil, noDecrypt
	}

	enc, err := c.Plaintext.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	md, err := openpgp.ReadMessage(bytes.NewReader(enc), c.Decrypt, nil, nil)
	if err != nil {
		return nil, err
	}

	dec, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}

	return dec, nil
}

func (c *CryptCache) Put(ctx context.Context, key string, data []byte) error {
	if c.Encrypt == nil {
		return noEncrypt
	}

	encbuf := new(bytes.Buffer)
	encwr, err := openpgp.Encrypt(encbuf, c.Encrypt, nil, nil, nil)
	if err != nil {
		return err
	}

	decrd := bytes.NewReader(data)
	_, err = io.Copy(encwr, decrd)
	encwr.Close()
	if err != nil {
		return err
	}

	return c.Plaintext.Put(ctx, key, encbuf.Bytes())
}

func (c *CryptCache) Delete(ctx context.Context, key string) error {
	return c.Plaintext.Delete(ctx, key)
}
