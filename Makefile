build:
	mkdir -p out
	CGO_ENABLED=0 go build -o out/server cmd/server/main.go
	CGO_ENABLED=0 go build -o out/encrypt cmd/encrypt/main.go
	CGO_ENABLED=0 go build -o out/decrypt cmd/decrypt/main.go
