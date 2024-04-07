package crypter

import (
	"context"
	"crypto"
	cryptoRand "crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"github.com/pkg/errors"
	"math/rand"
	"strings"
	"time"
	"os"

	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/goware/urlx"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"

	"github.com/anatol/clevis.go"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"

	"github.com/flatheadmill/tang-encryption-provider/handler"
)

func encode64(buffer []byte) string {
	return base64.RawURLEncoding.EncodeToString(buffer)
}

func decode64(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
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
	keyID       string
	headers     jwe.Headers
	exchangeKey jwk.Key
}

type Crypter struct {
	exchange	*Exchange
}

type Thumbprinter interface {
	Refresh() (error)
	Thumbprints() ([]string)
}

type StaticThumbprinter struct {
	thumbprints []string
}

func NewStaticThumbprinter (thumbprints string) (thumbprinter StaticThumbprinter) {
	split := strings.Split(thumbprints, ",")
	for i, _ := range split {
		split[i] = strings.TrimSpace(split[i])
	}
	return StaticThumbprinter{thumbprints: split}
}

func (r StaticThumbprinter) Refresh() (err error) {
	return nil
}

func (r StaticThumbprinter) Thumbprints() (thumbprints []string) {
	return r.thumbprints
}

type Advertiser interface {
	Resolve() ([]byte, error)
	URL() (string)
}

type StaticAdvertiser struct {
	advertisement string
	url string
}

func NewStaticAdvertiser (url string, advertisement string) (advertiser StaticAdvertiser) {
	return StaticAdvertiser{url: url, advertisement: advertisement}
}

func (r StaticAdvertiser) Resolve() (advertisement []byte, err error) {
	return []byte(r.advertisement), nil
}

func (r StaticAdvertiser) URL() (string) {
	return r.url
}

type TangAdvertiser struct {
	url string
}

func NewTangAdvertiser (url string) (advertiser TangAdvertiser) {
	return TangAdvertiser{url: url}
}

func (r TangAdvertiser) Resolve() (advertisement []byte, err error) {
	err2.Handle(&err)
	url := try.To1(urlx.Normalize(try.To1(urlx.Parse(strings.TrimSuffix(r.url, "/")))))
	advGet := try.To1(http.Get(fmt.Sprintf("%s/adv", url)))
	defer advGet.Body.Close()
	return try.To1(ioutil.ReadAll(advGet.Body)), nil
}

func (r TangAdvertiser) URL() (string) {
	return r.url
}

var NoValidationKeysFound = fmt.Errorf("no advertised validation keys match thumbprints")

func getKey(keySet jwk.Set, sought jwk.KeyOperation, thumbprints []string) (key jwk.Key, err error) {
	defer err2.Handle(&err, handler.Handler(&err))
	ctx := context.Background()
	for iterator := keySet.Iterate(ctx); iterator.Next(ctx); {
		key := iterator.Pair().Value.(jwk.Key)
		for _, op := range key.KeyOps() {
			if op == sought {
				for _, thumbprint := range thumbprints {
					if thumbprint == encode64(try.To1(key.Thumbprint(crypto.SHA256))) {
						return key, nil
					}
				}
			}
		}
	}
	return nil, NoValidationKeysFound
}

func getSortedThumbprints(keySet jwk.Set, sought jwk.KeyOperation) (thumbprints []string, err error) {
	defer err2.Handle(&err)
	ctx := context.Background()
	for iterator := keySet.Iterate(ctx); iterator.Next(ctx); {
		key := iterator.Pair().Value.(jwk.Key)
		for _, op := range key.KeyOps() {
			if op == sought {
				thumbprints = append(thumbprints, encode64(try.To1(key.Thumbprint(crypto.SHA256))))
			}
		}
	}
	slices.Sort(thumbprints)
	return thumbprints, nil
}

func findKey(keySet jwk.Set, sought jwk.KeyOperation) (key jwk.Key, err error) {
	defer err2.Handle(&err, handler.Handler(&err))
	ctx := context.Background()
	for iterator := keySet.Iterate(ctx); iterator.Next(ctx); {
		key := iterator.Pair().Value.(jwk.Key)
		for _, op := range key.KeyOps() {
			if op == sought {
				return key, nil
			}
		}
	}
	return nil, fmt.Errorf("key for operation %s not found", sought)
}

func Thumbprints(advJSON []byte) (err error) {
	defer err2.Handle(&err, handler.Handler(&err))
	message := try.To1(jws.Parse(advJSON))
	keySet := try.To1(jwk.Parse(message.Payload()))
	ctx := context.Background()
	for iterator := keySet.Iterate(ctx); iterator.Next(ctx); {
		key := iterator.Pair().Value.(jwk.Key)
		fmt.Fprintf(os.Stderr, "%s\n", encode64(try.To1(key.Thumbprint(crypto.SHA256))))
		fmt.Fprintf(os.Stderr, "kid %v x\n", key.KeyID())
	}
	return nil
}

func getExchangeKey(url string, advJSON []byte, thumbprints []string) (k *Exchange, err error) {
	message := try.To1(jws.Parse(advJSON))
	keySet := try.To1(jwk.Parse(message.Payload()))

	verifyKey := try.To1(getKey(keySet, jwk.KeyOpVerify, thumbprints))
	try.To1(jws.Verify(advJSON, jwa.ES512, verifyKey))

	sorted := try.To1(getSortedThumbprints(keySet, jwk.KeyOpDeriveKey))
	if len(sorted) == 0 {
		return nil, fmt.Errorf("no derive keys found in advertisement")
	}

	exchangeKey := try.To1(getKey(keySet, jwk.KeyOpDeriveKey, []string{ sorted[0] }))
	try.To(exchangeKey.Set(jwk.KeyOpsKey, jwk.KeyOperationList{}))
	try.To(exchangeKey.Set(jwk.AlgorithmKey, ""))

	headers := jwe.NewHeaders()

	try.To(headers.Set(jwe.KeyIDKey, encode64(try.To1(exchangeKey.Thumbprint(crypto.SHA256)))))
	try.To(headers.Set(jwe.ContentEncryptionKey, jwa.A256GCM))
	try.To(headers.Set(jwe.AlgorithmKey, jwa.ECDH_ES))

	clevis := try.To1(json.Marshal(&jsonClevis{
		Plugin: "tang",
		Tang: jsonTang{
			Location:      url,
			Advertisement: message.Payload(),
		},
	}))
	try.To(headers.Set("clevis", json.RawMessage(clevis)))

	return &Exchange {
		keyID:       sorted[0],
		headers:     headers,
		exchangeKey: exchangeKey,
	}, nil
}

func getExcahngeKeyAndMaybeRefresh(thumbprinter Thumbprinter, advertiser Advertiser) (k *Exchange, err error) {
	defer err2.Handle(&err)
	advertisement := try.To1(advertiser.Resolve())
	stuff, err := getExchangeKey(advertiser.URL(), advertisement, thumbprinter.Thumbprints())
	if try.Is(err, NoValidationKeysFound) {
		thumbprinter.Refresh()
		stuff = try.To1(getExchangeKey("", advertisement, thumbprinter.Thumbprints()))
	}
	return stuff, nil
}

type RotatingCrypter struct {
	thumbprinter Thumbprinter
	advertiser Advertiser
}

func NewRotatingCrypter(thumbprinter Thumbprinter, advertiser Advertiser) (crypter *RotatingCrypter, err error) {
	return &RotatingCrypter{thumbprinter: thumbprinter, advertiser: advertiser}, nil
}

func (c RotatingCrypter) Status () (keyID string, err error) {
	defer err2.Handle(&err)
	exchange := try.To1(getExcahngeKeyAndMaybeRefresh(c.thumbprinter, c.advertiser))
	return exchange.keyID, nil
}

func NewCrypter(url string, thumbprint string) (crypter *Crypter, err error) {
	defer err2.Handle(&err, handler.Handler(&err))
	thumbprinter := NewStaticThumbprinter(thumbprint)
	advertiser := NewTangAdvertiser(url)
	exchange := try.To1(getExcahngeKeyAndMaybeRefresh(thumbprinter, advertiser))
	return &Crypter{ exchange: exchange }, nil
}

func (c *Crypter) Encrypt(plain []byte) (cipher []byte, err error) {
	defer err2.Handle(&err)
	return try.To1(jwe.Encrypt(plain, jwa.ECDH_ES, c.exchange.exchangeKey, jwa.A256GCM, jwa.NoCompress, jwe.WithProtectedHeaders(c.exchange.headers))), nil
}

func Decrypt(cipher []byte) (plain []byte, err error) {
	defer err2.Handle(&err)
	return try.To1(clevis.Decrypt(cipher)), nil
}

func (c Crypter) Health() error {
	randomPlaintext := RandomHex(8)
	cipher, err := c.Encrypt([]byte(randomPlaintext))
	if err != nil {
		return errors.Wrap(err, "failed to encrypt random text")
	}
	decryptedText, err := Decrypt(cipher)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt random cipher text")
	}
	if randomPlaintext != string(decryptedText) {
		return errors.Errorf("decrypted text does not equal input random text: want: %s got: %s", randomPlaintext, decryptedText)
	}
	return nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func RandomHex(n int) string {
	if n <= 0 {
		return ""
	}
	buf := make([]byte, (n/2)+(n%2))
	if _, err := cryptoRand.Read(buf); err != nil {
		fmt.Println(err)
		return ""
	}
	return hex.EncodeToString(buf)[:n]
}
