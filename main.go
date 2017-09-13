package main

import (
	"flag"
	"os"

	"github.com/vdesjardins/cert-monitor/controller"
)

var (
	configPath = flag.String("config", "/etc/cert-monitor.yml", "path to main configuration file")
	oneTime    = flag.Bool("onetime", false, "refresh certificates without entering the endless loop")
	noReload   = flag.Bool("noreload", false, "do not reload services associated with each certificate")
)

func main() {
	flag.Parse()

	if *oneTime == true {
		if err := controller.ExecOnce(*configPath, *noReload); err != nil {
			os.Exit(1)
		}
	} else {
		controller.ExecLoop(*configPath, *noReload)
	}
}
