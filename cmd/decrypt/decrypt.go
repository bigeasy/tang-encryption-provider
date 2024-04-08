package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"google.golang.org/grpc"

	pbv1 "k8s.io/kms/apis/v1beta1"

	"github.com/flatheadmill/tang-encryption-provider/crypter"
)

func decryptWithKMS(socket string) (err error) {
	input, err := ioutil.ReadAll(os.Stdin)
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

	plain, err := client.Decrypt(ctx, &pbv1.DecryptRequest{Cipher: input})
	if err != nil {
		return err
	}

	fmt.Print(string(plain.Plain))

	return nil
}

func decryptWithTang() (err error) {
	input, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	plain, err := crypter.Decrypt(input)
	if err != nil {
		return err
	}
	fmt.Print(string(plain))
	return nil
}

func main() {
	var (
		grpc = flag.String("grpc", "", "url of gRPC server")
	)
	flag.Parse()
	var err error
	if *grpc != "" {
		err = decryptWithKMS(*grpc)
	} else {
		err = decryptWithTang()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
}
