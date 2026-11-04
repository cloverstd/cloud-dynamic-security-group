package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cloverstd/cloud-dynamic-security-group/internal/cloud"
	"github.com/cloverstd/cloud-dynamic-security-group/internal/config"
	"github.com/cloverstd/cloud-dynamic-security-group/internal/publicip"
	"github.com/cloverstd/cloud-dynamic-security-group/internal/syncer"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stderr))
}

func run(ctx context.Context, args []string, output io.Writer) int {
	usage := func() { fmt.Fprintln(output, "Usage: cdsg <run|sync> --config config.yaml [--dry-run]") }
	if len(args) == 0 {
		usage()
		return 2
	}
	if args[0] == "--help" || args[0] == "-h" {
		usage()
		return 0
	}
	command := args[0]
	if command != "sync" && command != "run" {
		usage()
		return 2
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "config.yaml", "YAML configuration path")
	dry := flags.Bool("dry-run", false, "read only")
	if err := flags.Parse(args[1:]); err != nil {
		usage()
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		usage()
		return 2
	}
	log := slog.New(slog.NewTextHandler(output, nil))
	cfg, err := config.Load(*path)
	if err != nil {
		log.Error("configuration failed", "error", err)
		return 2
	}
	engine := syncer.Engine{Config: cfg, Detector: publicip.New(cfg.IPSources, cfg.Timeout), Factory: cloud.New, Log: log, DryRun: *dry}
	for {
		err = engine.Sync(ctx)
		if ctx.Err() != nil {
			return 0
		}
		if err != nil {
			log.Error("synchronization failed", "error", err)
		}
		if command == "sync" {
			if err != nil {
				return 1
			}
			return 0
		}
		timer := time.NewTimer(cfg.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0
		case <-timer.C:
		}
	}
}
