package collector

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"osquery_exporter/model"
	"osquery_exporter/osquery"
	"strconv"
	"sync"
	"time"
)

// singleQueryCollector represents a metric/query definition for a single osquery call
type singleQueryCollector interface {
	String() string
	Id() string
	Query() string
	Desc() *prometheus.Desc
	ValueType() prometheus.ValueType
	Value() string
	Labels() []string
}

// update maps the osquery query result to the singleQueryCollector and updates the provided channel accordingly
func update(sqc singleQueryCollector, result *model.OsqueryResult, ch chan<- prometheus.Metric) error {
	log.Debugf("updating metric %q", sqc.String())
	// metrics with no labels can only accept one result set
	if len(sqc.Labels()) == 0 && len(result.Items) > 1 {
		return fmt.Errorf("metrics with no labels can only accept one result set")
	}
	for _, item := range result.Items {
		value, ok := item[sqc.Value()]
		if !ok {
			return fmt.Errorf("query %q doesn't contain value key %q", sqc.Query(), sqc.Value())
		}
		valueAsFloat, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("query %q result %q can't be converted to float", sqc.Query(), value)
		}
		labels := []string{}
		for _, labelIdentifier := range sqc.Labels() {
			if label, ok := item[labelIdentifier]; ok {
				labels = append(labels, label)
			} else {
				return fmt.Errorf("query %q doesn't contain a label key %q", sqc.Query(), labelIdentifier)
			}
		}
		ch <- prometheus.MustNewConstMetric(
			sqc.Desc(),
			sqc.ValueType(),
			valueAsFloat,
			labels...,
		)
	}
	return nil
}

// OsqueryCollector represents a collector that collects metrics from a set of osquery queries. It implements
// prometheus Collector
type OsqueryCollector struct {
	runner         *osquery.OsqueryRunner
	collectors     map[string]singleQueryCollector
	queryDurations *prometheus.SummaryVec
	success        *prometheus.GaugeVec
	resultsets     *prometheus.GaugeVec
	throttle       *model.ThrottleState
}

// NewOsqueryCollector creates an OsQueryCollector from a given osquery-runner and a set of metric definitions
func NewOsqueryCollector(r *osquery.OsqueryRunner, m model.Metrics, t string) *OsqueryCollector {
	collectors := make(map[string]singleQueryCollector)
	for _, c := range m.Counters {
		log.Infof("adding %s to OsqueryCollector", c.String())
		collectors[c.Id()] = c
	}
	for _, cv := range m.CounterVecs {
		log.Infof("adding %s to OsqueryCollector", cv.String())
		collectors[cv.Id()] = cv
	}
	for _, g := range m.Gauges {
		log.Infof("adding %s to OsqueryCollector", g.String())
		collectors[g.Id()] = g
	}
	for _, gv := range m.GaugeVecs {
		log.Infof("adding %s to OsqueryCollector", gv.String())
		collectors[gv.Id()] = gv
	}
	ti, err := time.ParseDuration(t)
	if err != nil {
		log.Fatalf("could not parse throttle_interval: %s", err)
	}

	return &OsqueryCollector{
		runner:     r,
		collectors: collectors,
		queryDurations: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Namespace: "osquery_exporter",
				Name:      "query_duration",
				Help:      "Query duration",
			},
			[]string{"name"}),
		success: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "osquery_exporter",
				Name:      "query_success",
				Help:      "Query execution status",
			},
			[]string{"name"},
		),
		resultsets: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "osquery_exporter",
				Name:      "resultsets",
				Help:      "Number of query result sets",
			},
			[]string{"name"},
		),
		throttle: &model.ThrottleState{
			Interval: ti,
		},
	}
}

// Describe implements prometheus.Collector
func (c *OsqueryCollector) Describe(ch chan<- *prometheus.Desc) {
	c.queryDurations.Describe(ch)
	c.success.Describe(ch)
	c.resultsets.Describe(ch)
}

// Collect implements prometheus.Collector
func (c *OsqueryCollector) Collect(ch chan<- prometheus.Metric) {
	c.throttle.Lock.Lock()
	defer c.throttle.Lock.Unlock()
	if time.Now().After(c.throttle.LastRun.Add(c.throttle.Interval)) {
		wg := sync.WaitGroup{}
		wg.Add(len(c.collectors))
		for _, col := range c.collectors {
			go func(col singleQueryCollector) {
				defer wg.Done()
				result, err := c.runner.Run(col.Query())
				if err != nil {
					log.Errorf("failed to run query %s: %s", col.Query(), err)
					c.success.WithLabelValues(col.String()).Set(0.0)
					return
				}
				c.resultsets.WithLabelValues(col.String()).Set(float64(len(result.Items)))
				err = update(col, result, ch)
				if err != nil {
					log.Warnf("metric %s errors on update: %s", col.String(), err)
					c.success.WithLabelValues(col.String()).Set(0.0)
					return
				}
				log.Debugf("metric %s took %s seconds to run", col.String(), result.Runtime)
				c.queryDurations.WithLabelValues(col.String()).Observe(
					result.Runtime.Seconds(),
				)
				c.success.WithLabelValues(col.String()).Set(1.0)
			}(col)
		}
		c.queryDurations.Collect(ch)
		c.success.Collect(ch)
		c.resultsets.Collect(ch)
		wg.Wait()
		c.throttle.LastRun = time.Now()
	}
}
