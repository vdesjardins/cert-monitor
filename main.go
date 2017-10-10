package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/vdesjardins/cert-monitor/controller"
)

var (
	version = "undefined"

	configPath = flag.String("config", "/etc/cert-monitor.yml", "path to main configuration file")
	oneTime    = flag.Bool("onetime", false, "refresh certificates without entering the endless loop")
	noReload   = flag.Bool("noreload", false, "do not reload services associated with each certificate")
	certConfig = flag.String("certconfig", "", "path to a specific certificate configuration")
	status     = flag.Bool("status", false, "print status of all certificates managed by cert-monitor")
	ver        = flag.Bool("version", false, "print version and exit")
)

func main() {
	flag.Parse()

	if *ver == true {
		fmt.Println(version)
		os.Exit(0)
	}

	if *status == true {
		controller.PrintStatus(*configPath)
		os.Exit(0)
	}

	if *oneTime == true {
		if err := controller.ExecOnce(*configPath, *noReload, *certConfig); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	controller.ExecLoop(*configPath, *noReload)
}
