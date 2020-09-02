package main

import (
	"fmt"

	"github.com/r2dtools/a2conf/a2conf"
)

func main() {
	apacheCtl := a2conf.ApacheCtl{
		BinPath: "/usr/sbin/apache2ctl",
	}
	output, err := apacheCtl.ParseDefines()

	if err != nil {
		panic(fmt.Sprintf("could not execute: %v", err))
	}

	fmt.Printf("output: %v", output)

	configurator, err := a2conf.GetApacheConfigurator(a2conf.GetDefaults())

	if err != nil {
		panic(fmt.Sprintf("could not create apache configurator: %v", err))
	}

	vhosts, err := configurator.GetVhosts()

	if err != nil {
		panic(fmt.Sprintf("could not get virtual hosts: %v", err))
	}

	fmt.Printf("vhsosts: %v", vhosts)
}
