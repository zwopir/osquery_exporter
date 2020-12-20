package osquery

import "github.com/zwopir/osquery_exporter/model"

type OsqueryRunner interface {
	Run(query string) (*model.OsqueryResult, error)
}
