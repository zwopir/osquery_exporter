package main

import (
	"flag"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/zwopir/osquery_exporter/collector"
	"github.com/zwopir/osquery_exporter/model"
	"github.com/zwopir/osquery_exporter/osquery"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
)

var (
	configFile    = flag.String("config.file", "config.yaml", "Config file")
	listenAddress = flag.String("web.listen-address", ":9232", "Address on which to expose metrics and web interface.")
	metricsPath   = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
)

func main() {
	flag.Parse()

	config, err := parseConfig()
	if err != nil {
		log.Fatal(err)
	}

	runner, err := createQueryRunner(config)
	if err != nil {
		log.Fatal(err)
	}

	osqueryCollector := collector.NewOsqueryCollector(
		runner,
		config.Metrics,
	)

	prometheus.MustRegister(osqueryCollector)

	handler := promhttp.HandlerFor(prometheus.DefaultGatherer,
		promhttp.HandlerOpts{ErrorLog: log.NewErrorLogger()})

	http.Handle(*metricsPath, handler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Osquery Exporter</title></head>
			<body>
			<h1>Osquery Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
	})
	log.Infoln("Listening on", *listenAddress)
	err = http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		log.Fatal(err)
	}

}

func parseConfig() (*model.Config, error) {
	var config = model.Config{
		Path: *configFile,

		// set the osquery runtime mode enabled to maintain backwards-compatibility
		OsQueryRuntime: model.OsQueryRuntime{Enabled: true},
		OsQuerySocket:  model.OsQuerySocket{Enabled: false},
	}

	data, err := ioutil.ReadFile(*configFile)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func createQueryRunner(config *model.Config) (osquery.OsqueryRunner, error) {
	if config.OsQueryRuntime.Enabled {
		return osquery.NewRuntimeRunner(config)
	}

	if config.OsQuerySocket.Enabled {
		return osquery.NewSocketRunner(config)
	}

	return nil, fmt.Errorf("neither the 'runtime' nor 'socket' modes are enabled in %q", config.Path)
}
