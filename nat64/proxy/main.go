package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var configFile = flag.String("config", "", "A json file containing a set of config.")

func main() {
	flag.Parse()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	p := NewProxy()

	wg := new(sync.WaitGroup)
	eipsChan := make(chan *ExchangeData, 10)
	ctx, cancel := context.WithCancel(context.Background())

	for _, v := range p.EIPServers {
		wg.Add(1)
		info := &GetClientInfo{
			ip:       v.Ip,
			port:     v.Port,
			send:     eipsChan,
			interval: p.Interval,
			wg:       wg,
			zone:     v.Zone,
		}
		go getClient(ctx, info)
	}

	wg.Add(1)
	info := &SetClientInfo{
		ip:   p.IPv6Server.Ip,
		port: p.IPv6Server.Port,
		recv: eipsChan,
		wg:   wg,
	}
	go setClient(ctx, info)

	select {
	case <-sigs:
		fmt.Println("Get KeyBoard Interrupted.")
		cancel()
		wg.Wait()
		return
	}
}
