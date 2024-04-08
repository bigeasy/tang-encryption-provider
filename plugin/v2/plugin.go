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
	logger *slog.Logger
	crypter *crypter.Crypter
}

func New(logger *slog.Logger, crypter *crypter.Crypter) (*v2plugin) {
	return &v2plugin{logger: logger, crypter: crypter}
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
	return response, nil
}

func (g *v2plugin) Encrypt(ctx context.Context, request *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	exchange, err := g.crypter.GetExchangeKey()
	if err != nil {
		return nil, fmt.Errorf("unable to obtain exchange key: %w", err)
	}
	cipher, err := g.crypter.Encrypt(exchange, request.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt: %w", err)
	}
	return &pb.EncryptResponse{KeyId: exchange.KeyID, Ciphertext: cipher}, nil
}

func (g *v2plugin) Decrypt(ctx context.Context, request *pb.DecryptRequest) (response *pb.DecryptResponse, err error) {
	g.logger.Info("decrypting", slog.String("jwe", string(request.Ciphertext)))
	plain, err := crypter.Decrypt(request.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt: %w", err)
	}
	return &pb.DecryptResponse{Plaintext: plain}, nil
}

func (g *v2plugin) Register(s *grpc.Server) {
	g.logger.Info("reigstering")
	pb.RegisterKeyManagementServiceServer(s, g)
}
