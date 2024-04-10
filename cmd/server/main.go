package main

import (
	"fmt"
	"net/url"
	"strings"
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
	LogLevel         string `envconfig:"log_level"`
	Version          string `default:"v2"`
	UnixSocket       string `envconfig:"unix_socket" default:"/var/run/kmsplugin/socket.sock"`
	TangURL          string `envconfig:"tang_url"`
	Thumbprints      string `envconfig:"thumbprints"`
	ThumbprintURL    string `envconfig:"thumbprint_url"`
	ThumbprintCACert string `envconfig:"thumbprint_ca_cert"`
	MetricsPort   	 int 	`envconfig:"metrics_port" default:"8082"`
	MetricsPath   	 string `envconfig:"metrics_path" default:"/metrics"`
	HealthzPort      int 	`envconfig:"healthz_port" default:"8081"`
	HealthzPath      string `envconfig:"healthz_path" default:"/healthz"`
	HealthzTimeout	 int64  `envconfig:"healthz_grpc_call_timeout" default:"5000"`
}

func main() {
	abend := func (message string, err error) {
		slog.Error(message, slog.Any("err", err))
		os.Exit(1)
	}
	var spec Specification
	err := envconfig.Process("tang_kms", &spec)
	if err != nil {
		abend("unable to read environment", err)
	}
	var level slog.Leveler
	slog.Info("level", "foo", strings.ToLower(spec.LogLevel))
	slog.Info("level", "bar", spec.LogLevel)
	fmt.Println(spec.LogLevel)
	switch strings.ToLower(spec.LogLevel) {
	case "info":
		level = slog.LevelInfo
	case "debug":
		slog.Info("debug")
		level = slog.LevelDebug
	default:
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{ Level: level })))
	slog.Info("configuration",
		slog.String("log_level", spec.LogLevel),
		slog.String("version", spec.Version),
		slog.String("tang_url", spec.TangURL),
		slog.String("unix_socket", spec.UnixSocket),
		slog.String("thumbprints", spec.Thumbprints),
		slog.String("thumbprint_url", spec.ThumbprintURL),
		slog.String("thumbprint_ca_cert", spec.ThumbprintCACert),
		slog.Int("metrics_port", spec.MetricsPort),
		slog.String("metrics_path", spec.MetricsPath),
		slog.Int("healthz_port", spec.HealthzPort),
		slog.String("healthz_path", spec.HealthzPath),
		slog.Int64("healthz_timeout", spec.HealthzTimeout),
	)
	mm := plugin.NewMetricsManager(&url.URL{
		Host: fmt.Sprintf("127.0.0.1:%d", spec.MetricsPort),
		Path: spec.MetricsPath,
	})
	var g plugin.Plugin
	var healthz plugin.HealthChecker
	switch spec.Version {
	case "v1":
		thumbprinter, err := crypter.NewStaticThumbprinter(spec.Thumbprints)
		if err != nil {
			abend("configuration error", err)
		}
		advertiser := crypter.NewTangAdvertiser(spec.TangURL)
		crypter := crypter.NewCrypter(thumbprinter, advertiser)
		healthz = v1.NewHealthChecker()
		g, err = v1.New(crypter)
		if err != nil {
			abend("unable to initialize encryption", err)
		}
	case "v2":
		thumbprinter, err := crypter.NewStaticThumbprinter(spec.Thumbprints)
		if err != nil {
			abend("configuration error", err)
		}
		advertiser := crypter.NewTangAdvertiser(spec.TangURL)
		crypter := crypter.NewCrypter(thumbprinter, advertiser)
		healthz = v2.NewHealthChecker()
		g = v2.New(crypter)
	}
	gm := plugin.NewManager(g, spec.UnixSocket)
	callTimeout := time.Duration(spec.HealthzTimeout) * time.Millisecond
	hm := plugin.NewHealthChecker(healthz, spec.UnixSocket, callTimeout, &url.URL{
		Host: fmt.Sprintf("127.0.0.1:%d", spec.HealthzPort),
		Path: spec.HealthzPath,
	})
	err = plugin.Run(gm, hm, mm)
	if err != nil {
		abend("abend", err)
	}
}
