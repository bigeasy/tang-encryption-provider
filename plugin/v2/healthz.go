// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v2

import (
	"context"
	"fmt"
	"log/slog"

	pb "k8s.io/kms/apis/v2"

	"github.com/google/uuid"
	grpc "google.golang.org/grpc"
	"github.com/flatheadmill/tang-encryption-provider/plugin"
)

var _ plugin.HealthChecker = (*HealthChecker)(nil)

type HealthChecker struct {
}

func NewHealthChecker() *HealthChecker {
	return &HealthChecker{}
}

func (h *HealthChecker) PingRPC(ctx context.Context, conn *grpc.ClientConn) error {
	client := pb.NewKeyManagementServiceClient(conn)

	if _, err := client.Status(ctx, &pb.StatusRequest{}); err != nil {
		return fmt.Errorf("failed to retrieve version from gRPC endpoint: %w", err)
	}

	// Check response is actually "ok"

	slog.Debug("Successfully pinged gRPC")
	return nil
}

func (h *HealthChecker) PingKMS(ctx context.Context, conn *grpc.ClientConn) error {
	client := pb.NewKeyManagementServiceClient(conn)

	encryptResponse, err := client.Encrypt(ctx, &pb.EncryptRequest{
		Uid:       uuid.NewString(),
		Plaintext: []byte("secret"),
	})
	if err != nil {
		return fmt.Errorf("failed to ping KMS: %w", err)
	}

	if _, err = client.Decrypt(ctx, &pb.DecryptRequest{
		Uid:        uuid.NewString(),
		Ciphertext: []byte(encryptResponse.Ciphertext),
	}); err != nil {
		return fmt.Errorf("failed to ping KMS: %w", err)
	}

	slog.Debug("Successfully pinged KMS")
	return nil
}
