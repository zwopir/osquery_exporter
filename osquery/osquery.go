package osquery

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/prometheus/common/log"
	"os/exec"
	"osquery_exporter/model"
	"time"
)

// OsqueryRunner represents a command runner for osquery
type OsqueryRunner struct {
	executable string
	timeout    time.Duration
}

// NewRunner creates a new runner. The executable is looked up in $PATH if not provided as an absolute path
// timeout must be time.ParseDuration`able.
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

// Run runs the provided query. The command invocation is cancelled with SIGKILL after
// timeout
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
