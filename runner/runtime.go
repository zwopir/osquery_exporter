package runner

import (
	"context"
	"encoding/json"
	"github.com/prometheus/common/log"
	"github.com/zwopir/osquery_exporter/model"
	"os/exec"
	"time"
)

type RuntimeRunner struct {
	Binary  string
	Timeout time.Duration
}

func (r *RuntimeRunner) Run(query string) (*model.OsqueryResult, error) {
	var items []model.OsqueryItem

	begin := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.Binary, "--json", query)
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