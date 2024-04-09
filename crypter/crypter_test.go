package crypter

import (
	"testing"
	"fmt"
	"strings"
	"time"
	"path"
	"os"
	"github.com/stretchr/testify/assert"
	"log/slog"
)

type key struct {
	thumbprint string
	json string
}

var keys = map[string]key {
	"verify1": key{
		thumbprint: "2P5B1BrEu6ltBlfu8EWHUVxAJX6FRLCmTQUPsAHySa8",
		json: `{
			"alg": "ES512",
			"kty": "EC",
			"crv": "P-521",
			"x": "AJCrbFS1G3u2SxjJ3WViStrIp2dzut7RdXjregQxlGE3uAJoQnXSSQEx3JE8zmtT_GBRsRz7oMx3diIEnhqLMQoo",
			"y": "AXNLBGll9QMc7Kkz1gLgWVPOPXQWd87GGA4g658nBgGi396f0jBimtIdk-LPUCqa3bJZjd963-rpH8yfbOLZDxDc",
			"d": "AOS4GCrUkaAWem0iExEnn6fdshtneFZLCtwKS-n-JIYs1WviRyc1XDqjAdvhK7o1VJz40xLIZZFKq9lVT_QI-6oF",
			"key_ops": ["sign", "verify"]
		}`,
	},
	"derive1": key{
		thumbprint: "gWOHi5Tdcu10RKlTNOo7S8VvdN4a580N07dmU7HDqsM",
		json: `{
			"alg": "ECMR",
			"kty": "EC",
			"crv": "P-521",
			"x": "AZWjfI7xyz0ueTNHJHmeIyZNQtP-0ZJUM-z9kHbqkdcwgHrjLF8e6YhhM8WkDm1TyUSfIY0SrBue1jwx4O7RxD7P",
			"y": "AEKAvEx87TzD-IhkYYLT17XUFeF6rbtfQd6Z7D-fm7t8O1me761RSGxPzC_Nh0XWepKmvpI1qi_XRpYMSOHOEI6U",
			"d": "AU0YEuEd4nypa_jn4VjGUpT_yg-nhM7vfHUc2WGUgYt9JKl6g22-n3kUBF0TJsL9nJRK3r82U5becc5tkDxZVW9_",
			"key_ops": ["deriveKey"]
		}`,
	},
	"verify2": key{
		thumbprint: "fkCRLeUN3YozTn5g3aKxNy1EwyBOF8fFA-fmsoPJxUo",
		json: `{
			"alg": "ES512",
			"kty": "EC",
			"crv": "P-521",
			"x": "AVQQCjn4ySvvORJNdRyUN2crLz4yQf5YgWlRjitMUq3NOLZHmr06t2N71H3q7djsLIHd7wKZ4wrBZs-JEYaeSEoY",
			"y": "AOTEPw2qt7ydYIvJk5pplrkr6H03GDNtGOgSU06fHxFrBFSxyrKCnYEtnEJTfqDFIgAhevOxM1JQF6myO65shVat",
			"d": "AUd1CgtI56UesO1QM-EsmGPtxahDU-bKqH1JubdLOOeNNQBkixTGM-HouWUX2seepGLvPFFt7YctA0-8aPyeiXUC",
			"key_ops": ["sign", "verify"]
		}`,
	},
	"derive2": key{
		thumbprint: "UCPvN8PxVGWck72Tra2qgGzDC6l3VeR6y-coQFGbm9c",
		json: `{
			"alg": "ECMR",
			"kty": "EC",
			"crv": "P-521",
			"x": "AbsW1JRf1bByL1lXk_pDJQO1ZTdeCZuPzsn0s8AsK6P5BBzz0vnz5c25j-QcK8Tx8i3jODHV0ZXZRFF7VpSyyZjs",
			"y": "AHklbog5546zZ8c06A1GmgHmomtRKLnyQo0wFXxeFmezE7gMyJzYY4yzBXWut2HhNKq2H9_rZOfWyVFYkya8iok3",
			"d": "AHG6vJyToh7idqqTh58Lsg25KgHtIKKdJtzeg5YKk8h1qtVF_lh0FUB1kIjMfkAu7DRuE_WjQ5GXpjCsdIH08Hr7",
			"key_ops": ["deriveKey"]
		}`,
	},
}

var lvl = new(slog.LevelVar)

func setupSuite(m *testing.M) func(m *testing.M) {
	slog.Info("setup suite")
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	})))
	lvl.Set(slog.LevelDebug)
	return func(m *testing.M) {
		slog.Info("teardown suite")
		slog.Debug("teardown suite")
	}
}

func TestMain(m *testing.M) {
	os.Exit(func () int {
		teardown := setupSuite(m)
		defer teardown(m)
		return m.Run()
	} ())
}

func writeKey(t *testing.T, key string, now int64, test string) {
	f, err := os.Create(path.Join(os.Getenv("TANG_DATA"), fmt.Sprintf("%d-%s-%s.jwk", now, test, keys[key].thumbprint)))
	assert.NoError(t, err)
	_, err = f.WriteString(keys[key].json)
	assert.NoError(t, err)
}

func wipeDir(t *testing.T, now int64, test string) {
	f, err := os.Open(os.Getenv("TANG_DATA"))
	assert.NoError(t, err)
	defer f.Close()
	fileInfo, err := f.Readdir(-1)
	assert.NoError(t, err)
	for _, file := range fileInfo {
		if ! strings.HasPrefix(file.Name(), fmt.Sprintf("%d-%s-", now, test)) {
			slog.Info("delete", "file", path.Join(os.Getenv("TANG_DATA"), file.Name()))
			assert.NoError(t, os.Remove(path.Join(os.Getenv("TANG_DATA"), file.Name())))
		}
	}
}

func removeKey(t *testing.T, key string, now int64, test string) {
	from := path.Join(os.Getenv("TANG_DATA"), fmt.Sprintf("%d-%s-%s.jwk", now, test, keys[key].thumbprint))
	assert.NoError(t, os.Remove(from))
}

func TestStaticThumbprint(t *testing.T) {
	now := time.Now().Unix()
	slog.Info("test", "TANG_URL", os.Getenv("TANG_URL"), "TANG_DATA", os.Getenv("TANG_DATA"))
	writeKey(t, "verify1", now, "thumbprint")
	writeKey(t, "derive1", now, "thumbprint")
	wipeDir(t, now, "thumbprint")
	thumbprinter, err := NewStaticThumbprinter(strings.Join([]string{
		"2P5B1BrEu6ltBlfu8EWHUVxAJX6FRLCmTQUPsAHySa8/gWOHi5Tdcu10RKlTNOo7S8VvdN4a580N07dmU7HDqsM",
		"fkCRLeUN3YozTn5g3aKxNy1EwyBOF8fFA-fmsoPJxUo/UCPvN8PxVGWck72Tra2qgGzDC6l3VeR6y-coQFGbm9c",
	}, ","))
	assert.NoError(t, err)
	advertiser := NewTangAdvertiser(os.Getenv("TANG_URL"))
	crypter := NewCrypter(thumbprinter, advertiser)
	exchange, err := crypter.GetExchangeKey()
	if assert.NoError(t, err) {
		assert.Equal(t, "gWOHi5Tdcu10RKlTNOo7S8VvdN4a580N07dmU7HDqsM", exchange.KeyID)
	}
	cipher, err := crypter.Encrypt(exchange, []byte("hello"))
	plain, err := Decrypt(cipher)
	fmt.Println(string(plain))
	writeKey(t, "verify2", now, "thumbprint")
	writeKey(t, "derive2", now, "thumbprint")
	exchange, err = crypter.GetExchangeKey()
	if assert.NoError(t, err) {
		assert.Equal(t, "gWOHi5Tdcu10RKlTNOo7S8VvdN4a580N07dmU7HDqsM", exchange.KeyID)
	}
	removeKey(t, "verify1", now, "thumbprint")
	exchange, err = crypter.GetExchangeKey()
	if assert.NoError(t, err) {
		assert.Equal(t, "UCPvN8PxVGWck72Tra2qgGzDC6l3VeR6y-coQFGbm9c", exchange.KeyID)
	}
	removeKey(t, "verify2", now, "thumbprint")
	exchange, err = crypter.GetExchangeKey()
	assert.Error(t, err)
}
