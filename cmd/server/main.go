package main

import (
	"fmt"
	"net/url"
	"time"
	"github.com/flatheadmill/tang-encryption-provider/crypter"
	"os"
	"log/slog"

	"github.com/flatheadmill/tang-encryption-provider/plugin"
	v1 "github.com/flatheadmill/tang-encryption-provider/plugin/v1"
	v2 "github.com/flatheadmill/tang-encryption-provider/plugin/v2"
	"github.com/kelseyhightower/envconfig"
)

type Specification struct {
	TangURL          string `envconfig:"tang_url"`
	Thumbprints      string `envconfig:"thumbprints"`
	ThumbprintURL    string `envconfig:"thumbprint_url"`
	ThumbprintCACert string `envconfig:"thumbprint_ca_cert"`
	MetricsPort   	 int 	`envconfig:"metrics_port" default:"8082"`
	MetricsPath   	 string `envconfig:"metrics_path" default:"/metrics"`
	Version          string `default:"v2"`
	UnixSocket       string `envconfig:"unix_socket" default:"/var/run/kmsplugin/socket.sock"`
	HealthzPort      int 	`envconfig:"healthz_port" default:"8081"`
	HealthzPath      string `envconfig:"healthz_path" default:"/healthz"`
	HealthzTimeout	 int64  `envconfig:"healthz_grpc_call_timeout" default:"5000"`
}

func main() {
	var spec Specification
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	abend := func (message string, err error) {
		logger.Error(message, slog.Any("err", err))
		os.Exit(1)
	}
	err := envconfig.Process("tang_kms", &spec)
	if err != nil {
		abend("unable to read environment", err)
	}
	logger.Info("configuration",
		slog.String("thumbprints", spec.Thumbprints),
		slog.String("unix_socket", spec.UnixSocket),
		slog.String("version", spec.Version),
		slog.String("tang_url", spec.TangURL),
	)
	logger.Info("metrics port", slog.Int("metrics_port", spec.MetricsPort))
	mm := plugin.NewMetricsManager(logger, &url.URL{
		Host: fmt.Sprintf("127.0.0.1:%d", spec.MetricsPort),
		Path: spec.MetricsPath,
	})
	var g plugin.Plugin
	var healthz plugin.HealthChecker
	switch spec.Version {
	case "v1":
		thumbprinter := crypter.NewStaticThumbprinter(spec.Thumbprints)
		advertiser := crypter.NewTangAdvertiser(spec.TangURL)
		crypter := crypter.NewCrypter(thumbprinter, advertiser)
		healthz = v1.NewHealthChecker(logger)
		g, err = v1.New(logger, crypter)
		if err != nil {
			abend("unable to initialize encryption", err)
		}
	case "v2":
		thumbprinter := crypter.NewStaticThumbprinter(spec.Thumbprints)
		advertiser := crypter.NewTangAdvertiser(spec.TangURL)
		crypter := crypter.NewCrypter(thumbprinter, advertiser)
		healthz = v2.NewHealthChecker(logger)
		g = v2.New(logger, crypter)
	}
	gm := plugin.NewManager(g, spec.UnixSocket)
	callTimeout := time.Duration(spec.HealthzTimeout) * time.Millisecond
	hm := plugin.NewHealthChecker(logger, healthz, spec.UnixSocket, callTimeout, &url.URL{
		Host: fmt.Sprintf("127.0.0.1:%d", spec.HealthzPort),
		Path: spec.HealthzPath,
	})
	err = plugin.Run(logger, gm, hm, mm)
	if err != nil {
		abend("abend", err)
	}
}
