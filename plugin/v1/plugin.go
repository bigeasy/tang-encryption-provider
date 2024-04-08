package v1

import (
	"fmt"
	"context"
	"net"
	"log/slog"

	"google.golang.org/grpc"

	pb "k8s.io/kms/apis/v1beta1"

	"github.com/flatheadmill/tang-encryption-provider/crypter"
)

const (
	apiVersion     = "v1beta1"
	runtimeName    = "TangKMS"
	runtimeVersion = "0.0.1"
)

type Crypter interface {
	Encrypt(plain []byte) (cipher []byte, err error)
}

type v1plugin struct {
	exchange *crypter.Exchange
	crypter *crypter.Crypter
	logger  *slog.Logger
	net.Listener
	*grpc.Server
}

func New(logger *slog.Logger, crypter *crypter.Crypter) (*v1plugin, error) {
	exchange, err := crypter.GetExchangeKey()
	if err != nil {
		return nil, fmt.Errorf("unable to get exchange key: %w", err)
	}
	return &v1plugin{logger: logger, crypter: crypter, exchange: exchange}, nil
}

func (g *v1plugin) Version(ctx context.Context, request *pb.VersionRequest) (*pb.VersionResponse, error) {
	return &pb.VersionResponse{Version: apiVersion, RuntimeName: runtimeName, RuntimeVersion: runtimeVersion}, nil
}

func (g *v1plugin) Encrypt(ctx context.Context, request *pb.EncryptRequest) (response *pb.EncryptResponse, err error) {
	cipher, err := g.crypter.Encrypt(g.exchange, request.Plain)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt: %w", err)
	}
	g.logger.Info("encrypted", slog.String("jwe", string(cipher)))
	return &pb.EncryptResponse{Cipher: cipher}, nil
}

func (g *v1plugin) Decrypt(ctx context.Context, request *pb.DecryptRequest) (response *pb.DecryptResponse, err error) {
	g.logger.Info("decrypting", slog.String("jwe", string(request.Cipher)))
	plain, err := crypter.Decrypt(request.Cipher)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt: %w", err)
	}
	return &pb.DecryptResponse{Plain: plain}, nil
}

func (g *v1plugin) Register(s *grpc.Server) {
	pb.RegisterKeyManagementServiceServer(s, g)
}
