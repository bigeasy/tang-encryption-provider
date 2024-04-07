package crypter

import (
	"testing"
	"github.com/lainio/err2/try"
	"fmt"
	"os"
//	"github.com/ory/dockertest/v3"
//	"github.com/lainio/err2"
)

func TestGetExchangeKey(t *testing.T) {
	advJSON := `
		{
		  "payload": "eyJrZXlzIjogW3siYWxnIjogIkVDTVIiLCAia3R5IjogIkVDIiwgImNydiI6ICJQLTUyMSIsICJ4IjogIkFic1cxSlJmMWJCeUwxbFhrX3BESlFPMVpUZGVDWnVQenNuMHM4QXNLNlA1QkJ6ejB2bno1YzI1ai1RY0s4VHg4aTNqT0RIVjBaWFpSRkY3VnBTeXlaanMiLCAieSI6ICJBSGtsYm9nNTU0NnpaOGMwNkExR21nSG1vbXRSS0xueVFvMHdGWHhlRm1lekU3Z015SnpZWTR5ekJYV3V0MkhoTktxMkg5X3JaT2ZXeVZGWWt5YThpb2szIiwgImtleV9vcHMiOiBbImRlcml2ZUtleSJdfSwgeyJhbGciOiAiRUNNUiIsICJrdHkiOiAiRUMiLCAiY3J2IjogIlAtNTIxIiwgIngiOiAiQUVBRmpJN3ZXeFNoVGFldThmUnN2ZENiZTZ0bTd3LUMyd2EzcXRTd1ZEdk5jc2pzX1NWQUItZzBUYUk5OVptUnRMTnIyeUNMMjBRZ2NBbTJQZEptZmUzTyIsICJ5IjogIkFOcElWT3hFRmF0QXVXWjYwYkdpUXI1RllkLXdrakdpNkVYbnBpU0VIRmJfOHc5aWh1NFBzUTNQRlJpcjV4dk94bUpkQVo3MGxWR2lCcFVlaUI5YzItcHQiLCAia2V5X29wcyI6IFsiZGVyaXZlS2V5Il19LCB7ImFsZyI6ICJFUzUxMiIsICJrdHkiOiAiRUMiLCAiY3J2IjogIlAtNTIxIiwgIngiOiAiQUpDcmJGUzFHM3UyU3hqSjNXVmlTdHJJcDJkenV0N1JkWGpyZWdReGxHRTN1QUpvUW5YU1NRRXgzSkU4em10VF9HQlJzUno3b014M2RpSUVuaHFMTVFvbyIsICJ5IjogIkFYTkxCR2xsOVFNYzdLa3oxZ0xnV1ZQT1BYUVdkODdHR0E0ZzY1OG5CZ0dpMzk2ZjBqQmltdElkay1MUFVDcWEzYkpaamQ5NjMtcnBIOHlmYk9MWkR4RGMiLCAia2V5X29wcyI6IFsidmVyaWZ5Il19LCB7ImFsZyI6ICJFUzUxMiIsICJrdHkiOiAiRUMiLCAiY3J2IjogIlAtNTIxIiwgIngiOiAiQVZRUUNqbjR5U3Z2T1JKTmRSeVVOMmNyTHo0eVFmNVlnV2xSaml0TVVxM05PTFpIbXIwNnQyTjcxSDNxN2Rqc0xJSGQ3d0taNHdyQlpzLUpFWWFlU0VvWSIsICJ5IjogIkFPVEVQdzJxdDd5ZFlJdkprNXBwbHJrcjZIMDNHRE50R09nU1UwNmZIeEZyQkZTeHlyS0NuWUV0bkVKVGZxREZJZ0FoZXZPeE0xSlFGNm15TzY1c2hWYXQiLCAia2V5X29wcyI6IFsidmVyaWZ5Il19XX0",
		  "signatures": [
			{
			  "signature": "ALXcO_pEioY1-vIb4MHMAzJ8IsKilBwDSgeJzur2wBpIcOAvKVk37kyt41SvEwinkk_7IhudI63G_RZDkmcp1WUnAdzT9R4CVjCAlrxKYUaySktoy9yafMxLi01jyAjzwUaCry9TkKWnaGqUbfYVPys1zTcoznZgoaiQ40VLq-O_kKk8",
			  "protected": "eyJhbGciOiJFUzUxMiIsImN0eSI6Imp3ay1zZXQranNvbiJ9"
			},
			{
			  "protected": "eyJhbGciOiJFUzUxMiIsImN0eSI6Imp3ay1zZXQranNvbiJ9",
			  "signature": "AVkpEi4oS5vq9OVZ4JWpwIbrEzRivqb9PIeV_D7VH15S0RfVA0FlWo_huW-1VNWNCOMEXPrcob8mZegI-v8sdBJtAVHO6Ky0hvHMFhpDJjF0_XV-TSfgCMENv2a4BsUJo18Rojp3WrHwHctoppx9RFR5kP6DZisIKvKsi54xbLdBOA0K"
			}
		  ]
		}

	`
	thumbprinter := NewStaticThumbprinter("2P5B1BrEu6ltBlfu8EWHUVxAJX6FRLCmTQUPsAHySa8")
	advertiser := NewStaticAdvertiser("http://127.0.0.1:8080", advJSON)
	exchange := try.To1(getExcahngeKeyAndMaybeRefresh(thumbprinter, advertiser))
	if exchange.keyID != "4lMfqjgBHEHk4OoAKzM2JOXgcEqcBhtyA2IyDNqF_EU" {
		t.Fatalf("expected key %s and got %s", "4lMfqjgBHEHk4OoAKzM2JOXgcEqcBhtyA2IyDNqF_EU", exchange.keyID)
	}
}

func TestCrypter(t *testing.T) {
	fmt.Fprintf(os.Stderr, "%s\n", os.Getenv("TANG_URL"))
	crypter := try.To1(NewCrypter(os.Getenv("TANG_URL"), "2P5B1BrEu6ltBlfu8EWHUVxAJX6FRLCmTQUPsAHySa8"))
	ciphertext := try.To1(crypter.Encrypt([]byte("hello")))
	fmt.Fprintf(os.Stderr, "%s\n", ciphertext)
	plaintext := try.To1(Decrypt(ciphertext))
	if string(plaintext) != "hello" {
		t.Fatalf("crypter encryption failed")
	}
}

func TestNewRotatingCrypter(t *testing.T) {
	fmt.Fprintf(os.Stderr, "%s\n", os.Getenv("TANG_URL"))
	thumbprinter := NewStaticThumbprinter("2P5B1BrEu6ltBlfu8EWHUVxAJX6FRLCmTQUPsAHySa8")
	advertiser := NewTangAdvertiser(os.Getenv("TANG_URL"))
	crypter := try.To1(NewRotatingCrypter(thumbprinter, advertiser))
	keyID := try.To1(crypter.Status())
	if keyID != "4lMfqjgBHEHk4OoAKzM2JOXgcEqcBhtyA2IyDNqF_EU" {
		t.Fatalf("expected key %s and got %s", "4lMfqjgBHEHk4OoAKzM2JOXgcEqcBhtyA2IyDNqF_EU", keyID)
	}
}
