package main

import (
	"io"
	"log"
	"os"
)

var (
	LOG *log.Logger
)

func Debugln(args ...interface{}) {
	if Debug {
		LOG.Println(args...)
	}
}

func Debugf(format string, args ...interface{}) {
	if Debug {
		LOG.Printf(format, args...)
	}
}

func init() {
	errFile, err := os.OpenFile("nat64.check.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Open log file failed, error = %v.", err)
	}
	LOG = log.New(io.MultiWriter(os.Stderr, errFile), "", log.Ldate|log.Ltime|log.Lshortfile)
}
