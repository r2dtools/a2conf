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
}
