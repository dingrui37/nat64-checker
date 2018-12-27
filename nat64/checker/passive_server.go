package main

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"log"
	"nat64/proto"
	"net"
	"strconv"
	"time"
)

type server struct {
	size    int
	timeout int
}

func passiveStartCheck(timeout int, size int, in *proto.SetNAT64Request) {
	checker := NewChecker()
	checker.TimeOut = time.Duration(timeout) * time.Second
	checker.Size = size
	checker.dataLocalization(in)
	err := checker.Run()
	if err != nil {
		LOG.Printf("Passive check failed, error = %v.", err)
	}
}

func (s *server) SetNAT64(ctx context.Context, in *proto.SetNAT64Request) (*proto.SetNAT64Response, error) {
	//rpc调用触发检测，创建goroutine处理，保证rpc请求不会超时
	go passiveStartCheck(s.timeout, s.size, in)
	return &proto.SetNAT64Response{}, nil
}

func PassiveGetEIPsServer(port int, size int, timeout int) {
	lis, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	proto.RegisterProxyServiceServer(s, &server{size: size, timeout: timeout})
	reflection.Register(s)

	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
