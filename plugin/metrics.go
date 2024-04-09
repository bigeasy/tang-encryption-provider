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
	"net/http"
	"net/url"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics encapsulates functionality related to serving Prometheus metrics for kms-plugin.
type Metrics struct {
	servingURL *url.URL
}

func NewMetricsManager(servingURL *url.URL) *Metrics {
	return &Metrics{servingURL: servingURL}
}

// Serve creates http server for hosting Prometheus metrics.
func (m *Metrics) Serve() chan error {
	errorChan := make(chan error)
	mux := http.NewServeMux()
	mux.Handle(m.servingURL.EscapedPath(), promhttp.Handler())

	go func() {
		defer close(errorChan)
		slog.Info("registering metrics listener", slog.String("serving_url", m.servingURL.String()))
		errorChan <- http.ListenAndServe(m.servingURL.Host, mux)
	}()

	return errorChan
}
