package model

import (
	"crypto/md5"
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"
)

const namespace = "osquery_exporter"

// Config represents a osquery_exporter configuration
type Config struct {
	OsQueryRuntime   OsQueryRuntime `yaml:"runtime"`
	Metrics          Metrics        `yaml:"metrics"`
	ThrottleInterval string         `yaml:"throttle_interval"`
}

// ThrottleState holds throttle interval configuration and state
type ThrottleState struct {
	Lock     sync.Mutex
	LastRun  time.Time
	Interval time.Duration
}

// OsQueryRuntime holds the information for the osquery binary and command invocation
type OsQueryRuntime struct {
	Binary  string `yaml:"osquery"`
	Timeout string `yaml:"timeout"`
}

// Metrics holds the metric definitions that are converted to prometheus metrics
type Metrics struct {
	Counters    []Counter    `yaml:"counters"`
	CounterVecs []CounterVec `yaml:"countervecs"`
	Gauges      []Gauge      `yaml:"gauges"`
	GaugeVecs   []GaugeVec   `yaml:"gaugevecs"`
}

// Metric represents a basic osquery_exporter metric definition
type Metric struct {
	Name            string `yaml:"name"`
	Help            string `yaml:"help"`
	Querystring     string `yaml:"query"`
	ValueIdentifier string `yaml:"valueidentifier"`
}

// String() implements the Stringer interface and the collector.singleQueryCollector
// interface
func (m Metric) String() string {
	return m.Name
}

// Desc() implements the collector.singleQueryCollector interface.
// It returns a prometheus metric description
func (m Metric) Desc() *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", m.Name),
		m.Help, []string{}, nil,
	)
}

// Query() implements the collector.singleQueryCollector interface.
func (m Metric) Query() string {
	return m.Querystring
}

// Id() implements the collector.singleQueryCollector interface.
// It returns a unique ID of a metric definition. Metrics are considered unique, if the
// md5 sum of the querystring is unique
func (m Metric) Id() string {
	return id(m.Querystring)
}

// Value() implements the collector.singleQueryCollector interface.
// It returns the key of the osquery-json output that yields the prometheus
// metric(vec) value
func (m Metric) Value() string {
	return m.ValueIdentifier
}

// MetricVec represents a definition for a prometheus vector metric
type MetricVec struct {
	Metric          `yaml:",inline"`
	LabelIdentifier []string `yaml:"labelidentifier"`
}

// Labels() implements the collector.singleQueryCollector interface.
// It returns the keys which are used as prometheus metric vector labels
func (v MetricVec) Labels() []string {
	return v.LabelIdentifier
}

// Counter represents a counter metric definition
type Counter struct {
	Metric `yaml:",inline"`
}

// Labels() implements the collector.singleQueryCollector interface.
// For counters an empty array is returned
func (Counter) Labels() []string {
	return []string{}
}

// ValueType() implements the collector.singleQueryCollector interface.
// It returns the prometheus value type for a counter
func (Counter) ValueType() prometheus.ValueType {
	return prometheus.CounterValue
}

// Gauge represents a gauge metric definition
type Gauge struct {
	Metric `yaml:",inline"`
}

// Labels() implements the collector.singleQueryCollector interface.
// For gauges an empty array is returned
func (Gauge) Labels() []string {
	return []string{}
}

// ValueType() implements the collector.singleQueryCollector interface.
// It returns the prometheus value type for a gague
func (Gauge) ValueType() prometheus.ValueType {
	return prometheus.GaugeValue
}

// CounterVec represents a counter vector definition
type CounterVec struct {
	MetricVec `yaml:",inline"`
}

// ValueType() implements the collector.singleQueryCollector interface.
// It returns the prometheus value type for a counter
func (CounterVec) ValueType() prometheus.ValueType {
	return prometheus.CounterValue
}

// Desc() implements the collector.singleQueryCollector interface.
// It returns a prometheus metric description
func (cv CounterVec) Desc() *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", cv.Name),
		cv.Help, cv.LabelIdentifier, nil,
	)
}

// GaugeVec represents a gauge vector definition
type GaugeVec struct {
	MetricVec `yaml:",inline"`
}

// ValueType() implements the collector.singleQueryCollector interface.
// It returns the prometheus value type for a gauge
func (GaugeVec) ValueType() prometheus.ValueType {
	return prometheus.GaugeValue
}

// Desc() implements the collector.singleQueryCollector interface.
// It returns a prometheus metric description
func (gv GaugeVec) Desc() *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", gv.Name),
		gv.Help, gv.LabelIdentifier, nil,
	)
}

// OsqueryItem represents an osqueryi query result set
type OsqueryItem map[string]string

// OsqueryResults represents an osqueryi call result
type OsqueryResult struct {
	Items   []OsqueryItem
	Runtime time.Duration
}

func id(s string) string {
	md5sum := md5.Sum([]byte(s))
	return string(md5sum[:])
}
