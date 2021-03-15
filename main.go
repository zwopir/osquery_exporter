package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"gopkg.in/yaml.v2"
	"osquery_exporter/collector"
	"osquery_exporter/model"
	"osquery_exporter/osquery"

	"flag"
	"io/ioutil"
	"net/http"
)

func main() {
	var (
		configFile    = flag.String("config.file", "config.yaml", "Config file")
		listenAddress = flag.String("web.listen-address", ":9232", "Address on which to expose metrics and web interface.")
		metricsPath   = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	)
	flag.Parse()

	var config *model.Config

	data, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Fatal(err)
	}

	r, err := osquery.NewRunner(
		config.OsQueryRuntime.Binary,
		config.OsQueryRuntime.Timeout,
	)
	if err != nil {
		log.Fatal(err)
	}

	osqueryCollector := collector.NewOsqueryCollector(
		r,
		config.Metrics,
		config.ThrottleInterval,
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
