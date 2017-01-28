package collector

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/zwopir/osquery_exporter/model"
	"github.com/zwopir/osquery_exporter/osquery"
	"strconv"
	"sync"
)

type singleQueryCollector interface {
	String() string
	Id() string
	Query() string
	Desc() *prometheus.Desc
	ValueType() prometheus.ValueType
	Value() string
	Labels() []string
}

func update(sqc singleQueryCollector, result *model.OsqueryResult, ch chan<- prometheus.Metric) error {
	log.Debugf("updating metric %q", sqc.String())

	for _, item := range result.Items {
		value, ok := item[sqc.Value()]
		if !ok {
			return fmt.Errorf("query %q doesn't contain value key %q", sqc.Query(), sqc.Value())
		}
		valueAsFloat, err := strconv.ParseFloat(value, 64)
		if err != nil {
			fmt.Errorf("query %q result %q can't be converted to float", sqc.Query(), value)
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

type OsqueryCollector struct {
	runner         *osquery.OsqueryRunner
	collectors     map[string]singleQueryCollector
	queryDurations *prometheus.SummaryVec
	success        *prometheus.GaugeVec
	resultsets     *prometheus.GaugeVec
}

func NewOsqueryCollector(r *osquery.OsqueryRunner, m model.Metrics) *OsqueryCollector {
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
	}
}

func (c *OsqueryCollector) Describe(ch chan<- *prometheus.Desc) {
	c.queryDurations.Describe(ch)
	c.success.Describe(ch)
	c.resultsets.Describe(ch)
}

func (c *OsqueryCollector) Collect(ch chan<- prometheus.Metric) {
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

}
