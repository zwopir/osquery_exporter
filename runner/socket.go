package runner

import (
	"fmt"
	"github.com/kolide/osquery-go"
	osqueryThrift "github.com/kolide/osquery-go/gen/osquery"
	"github.com/zwopir/osquery_exporter/model"
	"sync"
	"time"
)

type SocketRunner struct {
	sync.Mutex

	Client  *osquery.ExtensionManagerClient
	Timeout time.Duration
}

func (r *SocketRunner) Run(query string) (*model.OsqueryResult, error) {
	var items []model.OsqueryItem

	begin := time.Now()

	r.Lock()
	defer r.Unlock()

	result, err := r.Client.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query encountered an error: %s", err)
	}

	if result.Status.Code != int32(osqueryThrift.ExtensionCode_EXT_SUCCESS) {
		return nil, fmt.Errorf("query failed: %s", result.Status.Message)
	}

	for _, entry := range result.Response {

		var item = make(model.OsqueryItem)
		for key, value := range entry {
			item[key] = value
		}

		items = append(items, item)
	}

	duration := time.Since(begin)
	return &model.OsqueryResult{
		Items:   items,
		Runtime: duration,
	}, nil

}
