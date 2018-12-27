package main

import (
	"fmt"
	"google.golang.org/grpc"
	"log"
	"time"
)

func activeStartCheck(ip string, port int, timeout int, size int) {
	conn, err := grpc.Dial(fmt.Sprintf("%s:%d", ip, port), grpc.WithInsecure())
	if err != nil {
		log.Printf("Cannot connect to gRPC server = %s:%d, error = %v\n.", ip, port, err)
	}

	defer conn.Close()

	//c := proto.NewNAT64ServiceClient(conn)
	//ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	//defer cancel()
	////r, err := c.GetNAT64(ctx, &proto.GetNAT64Request{})
	//if err != nil {
	//	return
	//}

	checker := NewChecker()
	checker.TimeOut = time.Duration(timeout) * time.Second
	checker.Size = size
	//checker.dataLocalization(r)

	err = checker.Run()
	if err != nil {
		LOG.Printf("Active check failed, error = %v.", err)
	}
}

func ActiveGetEIPsClient(ip string, port int, timeout int, size int, interval int) {
	timer := time.NewTimer(time.Duration(interval) * time.Second)
LOOP:
	for {
		select {
		case <-timer.C:
			go activeStartCheck(ip, port, timeout, size)
			break LOOP
		default:
		}
	}
}
