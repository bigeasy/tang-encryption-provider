package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"

	"google.golang.org/grpc"

	pbv1 "k8s.io/kms/apis/v1beta1"

	"github.com/flatheadmill/tang-encryption-provider/crypter"
)

func encryptWithKMS(socket string) (error) {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}

	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", addr)
	}

	conn, err := grpc.Dial(socket, grpc.WithContextDialer(dialer), grpc.WithInsecure())
	if err != nil {
		return err
	}

	defer conn.Close()

	client := pbv1.NewKeyManagementServiceClient(conn)

	ctx := context.Background()

	version, err := client.Version(ctx, &pbv1.VersionRequest{})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "%v\n", version)

	cipher, err := client.Encrypt(ctx, &pbv1.EncryptRequest{Plain: input})
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", cipher.Cipher)

	return nil
}

func encryptWithTang(url string, thumbprint string) (err error) {
	input, err := ioutil.ReadAll(os.Stdin)
	if err != err {
		return err
	}
	thumbprinter := crypter.NewStaticThumbprinter(thumbprint)
	advertiser := crypter.NewTangAdvertiser(url)
	encrypter := crypter.NewCrypter(thumbprinter, advertiser)
	exchange, err := encrypter.GetExchangeKey()
	if err != nil {
		return err
	}
	compact, err := encrypter.Encrypt(exchange, input)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", compact)
	return nil
}

func main() {
	var (
		grpc       = flag.String("grpc", "", "url of gRPC server")
		tang       = flag.String("tang", "", "url of tang server")
		thumbprint = flag.String("thumbprint", "", "thumbprint of advertisement signing key")
	)
	flag.Parse()
	var err error
	if *grpc != "" {
		err = encryptWithKMS(*grpc)
	} else {
		err = encryptWithTang(*tang, *thumbprint)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, ">> %v\n", err)
	}
}
