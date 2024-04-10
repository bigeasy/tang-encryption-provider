package v2

import (
	"fmt"
	"context"
	"log/slog"

	"google.golang.org/grpc"

	pb "k8s.io/kms/apis/v2"

	"github.com/flatheadmill/tang-encryption-provider/crypter"
)

type v2plugin struct {
	crypter *crypter.Crypter
}

func New(crypter *crypter.Crypter) (*v2plugin) {
	return &v2plugin{crypter: crypter}
}

func (g *v2plugin) Status(ctx context.Context, request *pb.StatusRequest) (*pb.StatusResponse, error) {
	response := &pb.StatusResponse{
		Version: "v2beta1",
		Healthz: "ok",
		KeyId:   "",
	}
	exchange, err := g.crypter.GetExchangeKey()
	if err != nil {
		response.Healthz = fmt.Sprintf("unable to obtain exhange key: %w", err)
	} else {
		response.KeyId = exchange.KeyID
	}
	slog.Debug("status",
		slog.String("version", response.Version),
		slog.String("healthz", response.Healthz),
		slog.String("key_id", response.KeyId),
	)
	return response, nil
}

func (g *v2plugin) Encrypt(ctx context.Context, request *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	response, err := func() (*pb.EncryptResponse, error) {
		exchange, err := g.crypter.GetExchangeKey()
		if err != nil {
			return nil, fmt.Errorf("unable to obtain exchange key: %w", err)
		}
		cipher, err := g.crypter.Encrypt(exchange, request.Plaintext)
		if err != nil {
			return nil, fmt.Errorf("unable to encrypt: %w", err)
		}
		annotations := make(map[string][]byte)
		annotations["flatheadmill.github.io"] = cipher
		return &pb.EncryptResponse{KeyId: exchange.KeyID, Ciphertext: []byte{ 0 }, Annotations: annotations}, nil
	} ()
	if err != nil {
		slog.Warn("encrypt", slog.String("uuid", request.Uid), slog.String("err", err.Error()))
	} else {
		slog.Debug("encrypt", slog.String("uuid", request.Uid), slog.String("key_id", response.KeyId))
	}
	return response, err
}

func (g *v2plugin) Decrypt(ctx context.Context, request *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	response, err := func() (*pb.DecryptResponse, error) {
		if len(request.Ciphertext) != 1 && request.Ciphertext[0] != 0 {
			return nil, fmt.Errorf("unexpected ciphertext placeholder")
		}
		cipher, ok := request.Annotations["flatheadmill.github.io"]
		if ! ok {
			return nil, fmt.Errorf("ciphertext annotation missing")
		}
		plain, err := crypter.Decrypt(cipher)
		if err != nil {
			return nil, fmt.Errorf("unable to decrypt: %w", err)
		}
		return &pb.DecryptResponse{Plaintext: plain}, nil
	} ()
	if err != nil {
		slog.Warn("decrypt",
			slog.String("uuid", request.Uid),
			slog.String("key_id", request.KeyId),
			slog.String("err", err.Error()),
		)
	} else {
		slog.Debug("decrypt",
			slog.String("uuid", request.Uid),
			slog.String("key_id", request.KeyId),
		)
	}
	return response, err
}

func (g *v2plugin) Register(s *grpc.Server) {
	slog.Info("reigstering v2 plugin")
	pb.RegisterKeyManagementServiceServer(s, g)
}
