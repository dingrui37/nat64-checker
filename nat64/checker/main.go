package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

var Debug = false

type EIP struct {
	IPv4 string
	IPv6 string
}

type ConfigEIPs struct {
	EIPs []*EIP
}

func loadConfigs(filePath string, v interface{}) {
	var data []byte
	if filePath != "" {
		var err error
		data, err = ioutil.ReadFile(filePath)
		if err != nil {
			log.Fatalf("Failed to load default features: %v", err)
		} else {
			log.Fatalf("Failed to load default features: %v")
		}

		if err := json.Unmarshal(data, &v); err != nil {
			log.Fatalf("Failed to load default features: %v", err)
		}
	} else {

	}
}

func parseActiveAddr(addr string) (string, int) {
	if i := strings.Index(addr, ":"); i < 0 {
		log.Fatalf("%v", "gRPC server addr format error.")
	}

	addrSlice := strings.Split(addr, ":")
	ip := (&net.IPAddr{IP: net.ParseIP(addrSlice[0])}).String()
	var err error
	var port int

	if port, err = strconv.Atoi(addrSlice[1]); err != nil {
		log.Fatalf("%v", "gRPC server port = %s invalid.", port)
	}

	return ip, port
}

func main() {
	//通用参数
	timeout := flag.Int("timeout", 10, "Timeout(s) for every check.")
	size := flag.Int("size", 8, "ICMP packet data size.")
	debug := flag.Bool("debug", false, "Enable output debug info.")

	//互斥参数, 配置模式、主动获取模式、被动接受模式
	//config模式下需要指定配置文件以及检测频率
	config := flag.Bool("config", false, "Config mode, read EIPs from config file.")
	file := flag.String("file", "", "The config file used in config mode.")

	//被动模式下检测频率由client推送频率来决定
	passive := flag.Bool("passive", false, "Passive mode, external will push EIPs.")
	listen := flag.Int("listen", 50051, "Passive mode listen port.")

	//主动模式下，需要指定检测频率,有interval参数决定
	active := flag.Bool("active", false, "Active mode, checker will get EIPs from gRPC server.")
	addr := flag.String("addr", "172.18.39.187:9001", "The gRPC server addr for active mode.")

	interval := flag.Int("interval", 30, "Check interval(s), once for default.")
	flag.Parse()

	Debug = *debug

	if *config {
		loadConfigs(*file, )
	} else if *active {
		ip, port := parseActiveAddr(*addr)
		go ActiveGetEIPsClient(ip, port, *timeout, *size, *interval)
	} else if *passive {
		go PassiveGetEIPsServer(*listen, *timeout, *size)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigs:
		fmt.Println("Get Interrupted.")
		return
	}

}
