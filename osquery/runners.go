package osquery

import (
	"fmt"
	"github.com/kolide/osquery-go"
	"github.com/prometheus/common/log"
	"github.com/zwopir/osquery_exporter/model"
	"github.com/zwopir/osquery_exporter/runner"
	"os/exec"
	"time"
)

// NewRuntimeRunner creates a new osquery query runner using a given osqueryi binary
func NewRuntimeRunner(config *model.Config) (OsqueryRunner, error) {
	timeout, err := parseTimeout(config.OsQueryRuntime.Timeout)
	if err != nil {
		return nil, err
	}

	binary, err := exec.LookPath(config.OsQueryRuntime.Binary)
	if err != nil {
		return nil, fmt.Errorf("osqueryi binary not found in %s: %s", binary, err)
	}

	log.Infof("creating runtime runner with binary %q and timeout %s", config.OsQueryRuntime.Binary, timeout)
	return &runner.RuntimeRunner{
		Binary:  binary,
		Timeout: timeout,
	}, nil
}

// NewSocketRunner creates a new osquery query runner using a given osquery Thrift API extension socket
func NewSocketRunner(config *model.Config) (OsqueryRunner, error) {
	timeout, err := parseTimeout(config.OsQuerySocket.Timeout)
	if err != nil {
		return nil, err
	}

	client, err := osquery.NewClient(config.OsQuerySocket.Path, timeout)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to given socket file: %s", err)
	}

	log.Infof("creating osquery Thrift API client with socket %q with and %s", config.OsQuerySocket.Path, timeout)
	return &runner.SocketRunner{
		Client:  client,
		Timeout: timeout,
	}, nil
}

func parseTimeout(value string) (time.Duration, error) {
	timeout, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("can't parse timeout %q to time.Duration instance: %s", value, err)
	}

	return timeout, nil
}
