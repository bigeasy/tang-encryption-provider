package crypter

import (
	"context"
	"crypto"
	"errors"
	"fmt"
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

func parseThumbprints(thumbprints string) ([]string, error) {
	pairs := make([]string, 8)
	for _, pair := range strings.Split(thumbprints, ",") {
		trimmed := strings.TrimSpace(pair)
		pair := strings.Split(trimmed, "/")
		if (len(pair) != 2) {
			return nil, fmt.Errorf("malformed thumbprint pair: %s", trimmed)
		}
		pairs = append(pairs, strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1]))
	}
	return pairs, nil
}

func NewStaticThumbprinter (thumbprints string) (*staticThumbprinter, error) {
	split := strings.Split(thumbprints, ",")
	for i, _ := range split {
		split[i] = strings.TrimSpace(split[i])
	}
	pairs, err := parseThumbprints(thumbprints)
	if err != nil {
		return nil, err
	}
	return &staticThumbprinter{thumbprints: pairs}, nil
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

func getExchangeKey(url string, advJSON []byte, thumbprints []string) (k *Exchange, err error) {
	message, err := jws.Parse(advJSON)
	if err != nil {
		return nil, fmt.Errorf("unable to parse advertisement JSON: %w", err)
	}

	keySet, err := jwk.Parse(message.Payload())
	if err != nil {
		return nil, fmt.Errorf("unable to parse advertisement key set: %w", err)
	}

	keys, err := func() (map[string]jwk.Key, error) {
		keys := make(map[string]jwk.Key)
		ctx := context.Background()
		for iterator := keySet.Iterate(ctx); iterator.Next(ctx); {
			key := iterator.Pair().Value.(jwk.Key)
			thumbprint, err := key.Thumbprint(crypto.SHA256)
			if err != nil {
				return nil, fmt.Errorf(`unable to get thumbprint for "%s" key: %w`, key.KeyOps(), err)
			}
			keys[encode64(thumbprint)] = key
		}
		return keys, nil
	} ()
	if err != nil {
		return nil, err
	}

	i := func() (int) {
		for i := 0; i < len(thumbprints); i+=2 {
			if verifyKey, ok := keys[thumbprints[i]]; ok {
				for _, op := range verifyKey.KeyOps() {
					if op == jwk.KeyOpVerify {
						return i
					}
				}
			}
		}
		return -1
	} ()
	if i == -1 {
		return nil, NoValidationKeysFound
	}

	_, err = jws.Verify(advJSON, jwa.ES512, keys[thumbprints[i]])
	if err != nil {
		return nil, fmt.Errorf("signature invalid: %w", err)
	}

	exchangeKey, ok := keys[thumbprints[i + 1]]
	if ! ok {
		return nil, fmt.Errorf("cannot find exchange key: %s", thumbprints[i + 1])
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
		KeyID:       thumbprints[i + 1],
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
