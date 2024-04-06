package plugin

import (
	"context"
	"net"
	"os"
	"strings"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"google.golang.org/grpc"

	"github.com/flatheadmill/tang-encryption-provider/crypter"
	"github.com/flatheadmill/tang-encryption-provider/handler"
)

const (
	netProtocol    = "unix"
	apiVersion     = "v1beta1"
	runtimeName    = "TangKMS"
	runtimeVersion = "0.0.1"
)

type Crypter interface {
	Encrypt(plain []byte) (cipher []byte, err error)
}

type Plugin struct {
	crypter Crypter
	socket  string
	logger  logger
	net.Listener
	*grpc.Server
}

type logger interface {
	Msg(msg string)
	Msgf(format string, a ...any)
	MsgWithFields(fields map[string]interface{}, msg string)
	Err(err error) bool
}

type LogFields map[string]interface{}

func New(l logger, crypter Crypter, socket string) (plugin *Plugin, err error) {
	defer err2.Handle(&err, handler.Handler(&err))

	return &Plugin{crypter: crypter, socket: socket, logger: l}, nil
}

func (g *Plugin) Version(ctx context.Context, request *VersionRequest) (*VersionResponse, error) {
	return &VersionResponse{Version: apiVersion, RuntimeName: runtimeName, RuntimeVersion: runtimeVersion}, nil
}

// TODO Notify only of error and add metrics.
func (g *Plugin) Encrypt(ctx context.Context, request *EncryptRequest) (response *EncryptResponse, err error) {
	defer err2.Handle(&err, handler.Handler(&err))
	cipher := try.To1(g.crypter.Encrypt(request.Plain))
	g.logger.MsgWithFields(LogFields{"jwe": string(cipher)}, "encrypted")
	return &EncryptResponse{Cipher: cipher}, nil
}

// TODO Notify only of error and add metrics.
func (g *Plugin) Decrypt(ctx context.Context, request *DecryptRequest) (response *DecryptResponse, err error) {
	defer err2.Handle(&err, handler.Handler(&err))
	g.logger.MsgWithFields(LogFields{"jwe": string(request.Cipher)}, "decrypting")
	plain := try.To1(crypter.Decrypt(request.Cipher))
	return &DecryptResponse{Plain: plain}, nil
}

func (g *Plugin) setupRPCServer() (err error) {
	defer err2.Handle(&err, handler.Handler(&err))

	// @ implies the use of Linux socket namespace - no file on disk and nothing
	// to clean-up.
	if !strings.HasPrefix(g.socket, "@") {
		try.To(func() error {
			err = os.Remove(g.socket)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		}())
	}

	g.Listener = try.To1(net.Listen(netProtocol, g.socket))
	g.logger.Msgf("Listening on unix domain socket: %s", g.socket)

	g.Server = grpc.NewServer()
	RegisterKeyManagementServiceServer(g.Server, g)

	return nil
}

func (g *Plugin) ServeKMSRequests() (*grpc.Server, chan error) {
	errorChannel := make(chan error, 1)

	if err := g.setupRPCServer(); err != nil {
		errorChannel <- err
		close(errorChannel)
		return nil, errorChannel
	}

	go func() {
		defer close(errorChannel)
		errorChannel <- g.Serve(g.Listener)
	}()

	return g.Server, errorChannel
}
