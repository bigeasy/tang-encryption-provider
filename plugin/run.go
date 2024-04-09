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

// Binary kmsplugin - entry point into kms-plugin. See go/gke-secrets-encryption-design for details.
// https://law.stackexchange.com/questions/59999/can-i-copy-pieces-of-apache-licensed-source-code-if-i-attribute
package plugin

import (
	"os"
	"os/signal"
	"syscall"
	"log/slog"
)

func Run(logger *slog.Logger, p *PluginManager, h *HealthCheckerManager, m *Metrics) error {
	signalsChan := make(chan os.Signal, 1)
	signal.Notify(signalsChan, syscall.SIGINT, syscall.SIGTERM)

	metricsErrCh := m.Serve()
	healthzErrCh := h.Serve()

	gRPCSrv, kmsErrorCh := p.Start()
	defer gRPCSrv.GracefulStop()

	for {
		select {
		case sig := <-signalsChan:
			logger.Info("captured shutdown signal", slog.Any("signal", sig))
			return nil
		case kmsError := <-kmsErrorCh:
			return kmsError
		case metricsErr := <-metricsErrCh:
			logger.Warn("metrics error", slog.Any("err", metricsErr))
			metricsErrCh = nil
		case healthzErr := <-healthzErrCh:
			logger.Warn("healthz error", slog.Any("err", healthzErr))
			healthzErrCh = nil
		}
	}
}
