package crypter

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"strings"

	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/goware/urlx"

	"github.com/anatol/clevis.go"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
)

func encode64(buffer []byte) string {
	return base64.RawURLEncoding.EncodeToString(buffer)
}

type jsonTang struct {
	Location      string          `json:"url"`
	Advertisement json.RawMessage `json:"adv"`
}

type jsonClevis struct {
	Plugin string   `json:"pin"`
	Tang   jsonTang `json:"tang"`
}

type Exchange struct {
	KeyID       string
	headers     jwe.Headers
	exchangeKey jwk.Key
}

type Crypter struct {
	thumbprinter Thumbprinter
	advertiser Advertiser
}

type Thumbprinter interface {
	Refresh() (error)
	Thumbprints() ([]string)
}

type staticThumbprinter struct {
	thumbprints []string
}

func NewStaticThumbprinter (thumbprints string) staticThumbprinter {
	split := strings.Split(thumbprints, ",")
	for i, _ := range split {
		split[i] = strings.TrimSpace(split[i])
	}
	return staticThumbprinter{thumbprints: split}
}

func (r staticThumbprinter) Refresh() error {
	return nil
}

func (r staticThumbprinter) Thumbprints() (thumbprints []string) {
	return r.thumbprints
}

type Advertiser interface {
	Resolve() ([]byte, error)
	URL() (string)
}

type TangAdvertiser struct {
	url string
}

func NewTangAdvertiser (url string) (advertiser TangAdvertiser) {
	return TangAdvertiser{url: url}
}

func (r TangAdvertiser) Resolve() ([]byte, error) {
	url, err := func() (string, error) {
		parsed, err := urlx.Parse(strings.TrimSuffix(r.url, "/"))
		if err != nil {
			return "", err
		}
		normalized, err := urlx.Normalize(parsed)
		if err != nil {
			return "", err
		}
		return normalized, nil
	}()
	if err != nil {
		return nil, fmt.Errorf(`malformed url "%s": %w`, r.url, err)
	}
	body, err := func() ([]byte, error) {
		advGet, err := http.Get(fmt.Sprintf("%s/adv", url))
		if err != nil {
			return nil, err
		}
		defer advGet.Body.Close()
		body, err := ioutil.ReadAll(advGet.Body)
		if err != nil {
			return nil, err
		}
		return body, nil
	} ()
	if err != nil {
		return nil, fmt.Errorf("HTTP GET to Tang for advertisement failed: %w", err)
	}
	return body, nil
}

func (r TangAdvertiser) URL() (string) {
	return r.url
}

var NoValidationKeysFound = fmt.Errorf("no advertised validation keys match thumbprints")

func getKey(keySet jwk.Set, operation jwk.KeyOperation, thumbprints []string) (key jwk.Key, err error) {
	ctx := context.Background()
	for iterator := keySet.Iterate(ctx); iterator.Next(ctx); {
		key := iterator.Pair().Value.(jwk.Key)
		for _, op := range key.KeyOps() {
			if op == operation {
				for _, thumbprint := range thumbprints {
					actual, err := key.Thumbprint(crypto.SHA256)
					if err != nil {
						return nil, fmt.Errorf(`unable to get thumbprint for "%s" key: %w`, op, err)
					}
					if thumbprint == encode64(actual) {
						return key, nil
					}
				}
			}
		}
	}
	return nil, nil
}

func getSortedThumbprints(keySet jwk.Set, operation jwk.KeyOperation) (thumbprints []string, err error) {
	ctx := context.Background()
	for iterator := keySet.Iterate(ctx); iterator.Next(ctx); {
		key := iterator.Pair().Value.(jwk.Key)
		for _, op := range key.KeyOps() {
			if op == operation {
				thumbprint, err := key.Thumbprint(crypto.SHA256)
				if err != nil {
					return nil, fmt.Errorf(`unable to get thumbprint for "%s" key: %w`, op, err)
				}
				thumbprints = append(thumbprints, encode64(thumbprint))
			}
		}
	}
	slices.Sort(thumbprints)
	return thumbprints, nil
}

func getExchangeKey(url string, advJSON []byte, thumbprints []string) (k *Exchange, err error) {
	message, err := jws.Parse(advJSON)
	if err != nil {
		return nil, fmt.Errorf("unable to parse advertisement JSON: %w", err)
	}

	keySet, err := jwk.Parse(message.Payload())
	if err != nil {
		return nil, fmt.Errorf("unable to parse advertisement key set: %w", err)
	}

	verifyKey, err := getKey(keySet, jwk.KeyOpVerify, thumbprints)
	if err != nil {
		return nil, err
	}
	if verifyKey == nil {
		return nil, NoValidationKeysFound
	}

	_, err = jws.Verify(advJSON, jwa.ES512, verifyKey)
	if err != nil {
		return nil, fmt.Errorf("signature invalid: %w", err)
	}

	sorted, err := getSortedThumbprints(keySet, jwk.KeyOpDeriveKey)
	if err != nil {
		return nil, err
	}
	if len(sorted) == 0 {
		return nil, fmt.Errorf("no derive keys found in advertisement")
	}

	exchangeKey, err := getKey(keySet, jwk.KeyOpDeriveKey, []string{ sorted[0] })
	if err != nil {
		return nil, err
	}

	err = func() (err error) {
		err = exchangeKey.Set(jwk.KeyOpsKey, jwk.KeyOperationList{})
		if err != nil {
			return err
		}
		err = exchangeKey.Set(jwk.AlgorithmKey, "")
		if err != nil {
			return err
		}
		return nil
	} ()
	if err != nil {
		return nil, fmt.Errorf("unable to format exchange key: %w", err)
	}

	headers := jwe.NewHeaders()

	// Okay, this is stupid. Why am I doing this? I want an exception handling
	// system that will throw a stack trace and take me to where these errors
	// occurred if there is something about these function calls that actually
	// generates and error. I'll never handle them, it would only be due to a
	// misconfiguratio or bug in the jwx library or Tang or elsewhere.

	err = func() (err error) {
		thumbprint, err := exchangeKey.Thumbprint(crypto.SHA256)
		if err != nil {
			return err
		}
		err = headers.Set(jwe.KeyIDKey, encode64(thumbprint))
		if err != nil {
			return err
		}
		err = headers.Set(jwe.ContentEncryptionKey, jwa.A256GCM)
		if err != nil {
			return err
		}
		err = headers.Set(jwe.AlgorithmKey, jwa.ECDH_ES)
		if err != nil {
			return err
		}
		clevis, err := json.Marshal(&jsonClevis{
			Plugin: "tang",
			Tang: jsonTang{
				Location:      url,
				Advertisement: message.Payload(),
			},
		})
		if err != nil {
			return err
		}
		err = headers.Set("clevis", json.RawMessage(clevis))
		if err != nil {
			return err
		}
		return nil
	}()
	if err != nil {
		return nil, fmt.Errorf("unable to set exchange key headers: %w", err)
	}

	return &Exchange {
		KeyID:       sorted[0],
		headers:     headers,
		exchangeKey: exchangeKey,
	}, nil
}

func getExchangeKeyAndMaybeRefresh(thumbprinter Thumbprinter, advertiser Advertiser) (*Exchange, error) {
	advertisement, err := advertiser.Resolve()
	if err != nil {
		return nil, fmt.Errorf("advertisement HTTP GET failed: %w", err)
	}
	exchange, err := getExchangeKey(advertiser.URL(), advertisement, thumbprinter.Thumbprints())
	if err != nil {
		switch {
		case errors.Is(err, NoValidationKeysFound):
			thumbprinter.Refresh()
			exchange, err = getExchangeKey(advertiser.URL(), advertisement, thumbprinter.Thumbprints())
			if err != nil {
				return nil, err
			}
		default:
			return nil, err
		}
	}
	return exchange, nil
}

func NewCrypter(thumbprinter Thumbprinter, advertiser Advertiser) (crypter *Crypter) {
	return &Crypter{ thumbprinter: thumbprinter, advertiser: advertiser }
}

func (c *Crypter) GetExchangeKey() (*Exchange, error) {
	return getExchangeKeyAndMaybeRefresh(c.thumbprinter, c.advertiser)
}

func (c *Crypter) Encrypt(exchange *Exchange, plain []byte) ([]byte, error) {
	cipher, err := jwe.Encrypt(plain, jwa.ECDH_ES, exchange.exchangeKey, jwa.A256GCM, jwa.NoCompress, jwe.WithProtectedHeaders(exchange.headers))
	if err != nil {
		return nil, fmt.Errorf("encyption failed: %w", err)
	}
	return cipher, nil
}

func Decrypt(cipher []byte) ([]byte, error) {
	 plain, err := clevis.Decrypt(cipher)
	 if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	 }
	 return plain, nil
}
