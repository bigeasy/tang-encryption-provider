module github.com/flatheadmill/tang-encryption-provider

go 1.18

replace k8s.io/apiserver/0.23.5 => k8s.io/apiserver v0.23.5

require (
	github.com/anatol/clevis.go v0.0.0-20220325231436-1877edc32744
	github.com/flatheadmill/go-jose/v3 v3.0.2
	github.com/gogo/protobuf v1.3.2
	github.com/gorilla/mux v1.8.0
	github.com/goware/urlx v0.3.1
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lainio/err2 v1.0.0
	github.com/lestrrat-go/jwx v1.2.20
	github.com/pkg/errors v0.9.1
	github.com/rs/zerolog v1.26.1
	golang.org/x/net v0.0.0-20211209124913-491a49abca63
	google.golang.org/grpc v1.45.0
)

require (
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/go-jose/go-jose/v3 v3.0.0 // indirect
	github.com/goccy/go-json v0.9.5 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-tpm v0.3.3 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.8 // indirect
	github.com/lestrrat-go/blackmagic v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.0 // indirect
	github.com/lestrrat-go/iter v1.0.1 // indirect
	github.com/lestrrat-go/option v1.0.0 // indirect
	golang.org/x/crypto v0.0.0-20220315160706-3147a52a75dd // indirect
	golang.org/x/sys v0.0.0-20220315194320-039c03cc5b86 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20210831024726-fe130286e0e2 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	k8s.io/apiserver/0.23.5 v0.0.0-00010101000000-000000000000 // indirect
)
