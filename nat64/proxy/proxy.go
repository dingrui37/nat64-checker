package main

import (
	"context"
	"encoding/json"
	"fmt"
	"google.golang.org/grpc"
	"io/ioutil"
	"log"
	"nat64/proto"
	"sync"
	"time"
)

type Server struct {
	Zone string
	Ip   string
	Port int
}

type Proxy struct {
	EIPServers []*Server
	IPv6Server *Server
	Interval   int
}

type GetClientInfo struct {
	ip       string
	port     int
	send     chan *ExchangeData
	interval int
	wg       *sync.WaitGroup
	zone     string
}

type SetClientInfo struct {
	ip   string
	port int
	recv chan *ExchangeData
	wg   *sync.WaitGroup
}

type ExchangeData struct {
	response *proto.GetNAT64Response
	zone     string
}

func NewProxy() *Proxy {
	p := &Proxy{}
	p.loadConfigs(*configFile)
	return p
}

func (p *Proxy) loadConfigs(filePath string) {
	var data []byte
	if filePath != "" {
		var err error
		data, err = ioutil.ReadFile(filePath)
		if err != nil {
			log.Fatalf("Failed to read config file: %v.", err)
		}
	} else {
		log.Fatalf("Config file path is empty.")
	}

	if err := json.Unmarshal(data, &p); err != nil {
		log.Fatalf("Failed to parse config file: %v.", err)
	}
}

func getEIPs(ip string, port int) (*proto.GetNAT64Response, error) {
	conn, err := grpc.Dial(fmt.Sprintf("%s:%d", ip, port), grpc.WithInsecure())
	if err != nil {
		fmt.Printf("Cannot connect to gRPC server = %s:%d, error = %v.\n", ip, port, err)
		return nil, err
	}
	defer conn.Close()

	client := proto.NewNAT64ServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	return client.GetNAT64(ctx, &proto.GetNAT64Request{})
}

func getClient(ctx context.Context, info *GetClientInfo) {
	ticker := time.NewTicker(time.Duration(info.interval) * time.Second)
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Get EIPs client exit.")
			info.wg.Done()
			return
		case <-ticker.C:
			if r, err := getEIPs(info.ip, info.port); err == nil {
				info.send <- &ExchangeData{response: r, zone: info.zone}
			}
		}
	}
}

func setEIPs(ip string, port int, data *ExchangeData) {
	conn, err := grpc.Dial(fmt.Sprintf("%s:%d", ip, port), grpc.WithInsecure())
	if err != nil {
		fmt.Printf("Cannot connect to gRPC server = %s:%d, error = %v.\n", ip, port, err)
		return
	}
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	//收到的EIPs信息后加上zone信息传给检测工具
	request := &proto.SetNAT64Request{
		Request: &proto.GetNAT64Response{
			Retcode: data.response.Retcode,
			Message: data.response.Message,
			Nat64S:  data.response.Nat64S,
		},
		Zone: data.zone,
	}

	_, err = client.SetNAT64(ctx, request)
	if err != nil {
		fmt.Printf("Set EIPs by gRPC failed, error = %v\n.", err)
	}
}

func setClient(ctx context.Context, info *SetClientInfo) {
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Send EIPs client exit.")
			info.wg.Done()
			return
		case r := <-info.recv:
			setEIPs(info.ip, info.port, r)
		}
	}
}
