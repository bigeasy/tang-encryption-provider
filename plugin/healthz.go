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

package plugin

import (
	"net/url"
	"time"
	"log/slog"

	"context"
	"fmt"

	"google.golang.org/grpc/credentials/insecure"

	"net"
	"net/http"

	"google.golang.org/grpc"
)

// HealthCheckerManager types that encapsulates healthz functionality of kms-plugin.
// The following health checks are performed:
// 1. Getting version of the plugin - validates gRPC connectivity.
// 2. Asserting that the caller has encrypt and decrypt permissions on the crypto key.
type HealthCheckerManager struct {
	unixSocketPath string
	callTimeout    time.Duration
	servingURL     *url.URL

	checker HealthChecker
}

type HealthChecker interface {
	PingRPC(context.Context, *grpc.ClientConn) error
	PingKMS(context.Context, *grpc.ClientConn) error
}

func NewHealthChecker(checker HealthChecker, unixSocketPath string,
	callTimeout time.Duration, servingURL *url.URL) *HealthCheckerManager {

	return &HealthCheckerManager{
		unixSocketPath: unixSocketPath,
		callTimeout:    callTimeout,
		servingURL:     servingURL,
		checker:        checker,
	}
}

// Serve creates http server for hosting healthz.
func (m *HealthCheckerManager) Serve() chan error {
	errorCh := make(chan error)
	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("%s", m.servingURL.EscapedPath()), m.HandlerFunc)

	go func() {
		defer close(errorCh)
		slog.Info("registering healthz listener", slog.String("serving_url", m.servingURL.String()))
		select {
		case errorCh <- http.ListenAndServe(m.servingURL.Host, mux):
		default:
		}
	}()

	return errorCh
}

func (m *HealthCheckerManager) HandlerFunc(w http.ResponseWriter, r *http.Request) {
	err := func() error {
		ctx, cancel := context.WithTimeout(r.Context(), m.callTimeout)
		defer cancel()

		conn, err := dialUnix(m.unixSocketPath)
		if err != nil {
			return err
		}
		defer conn.Close()

		if err := m.checker.PingRPC(ctx, conn); err != nil {
			return err
		}

		if r.FormValue("ping-kms") == "true" {
			if err := m.checker.PingKMS(ctx, conn); err != nil {
				return err
			}
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		return nil
	} ()
	if err != nil {
		slog.Warn("healhz failed", err, err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	} else {
		slog.Debug("healhz called")
	}
}

func dialUnix(unixSocketPath string) (*grpc.ClientConn, error) {
	protocol, addr := "unix", unixSocketPath
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		if deadline, ok := ctx.Deadline(); ok {
			return net.DialTimeout(protocol, addr, time.Until(deadline))
		}
		return net.DialTimeout(protocol, addr, 0)
	}

	return grpc.Dial(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer))
}
