package osquery

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/prometheus/common/log"
	"os/exec"
	"github.com/zwopir/osquery_exporter/model"
	"time"
)

type OsqueryRunner struct {
	executable string
	timeout    time.Duration
}

func NewRunner(executable, timeout string) (*OsqueryRunner, error) {
	to, err := time.ParseDuration(timeout)
	if err != nil {
		return nil, fmt.Errorf("can't parse timeout for runner: %s", err)
	}
	exe, err := exec.LookPath(executable)
	if err != nil {
		return nil, fmt.Errorf("osqueryi executable not found in %s: %s", executable, err)
	}

	log.Infof("creating runner on executable %q with timeout %s", exe, timeout)
	return &OsqueryRunner{
		executable: exe,
		timeout:    to,
	}, nil
}

func (runner *OsqueryRunner) Run(query string) (*model.OsqueryResult, error) {
	var items []model.OsqueryItem
	begin := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), runner.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, runner.executable, "--json", query)
	// cmd := exec.Command(runner.executable, "--json", query)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	log.Debugf("running query %q", query)
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	if err := json.NewDecoder(stdout).Decode(&items); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	duration := time.Since(begin)
	return &model.OsqueryResult{
		Items:   items,
		Runtime: duration,
	}, nil
}
