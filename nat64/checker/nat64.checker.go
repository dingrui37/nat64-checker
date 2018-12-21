package main

import (
	"context"
	"flag"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"google.golang.org/grpc"
	"io"
	"log"
	"math/rand"
	"nat64/proto"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

const (
	TimeSliceLength  = 8
	ProtocolICMP     = 1
	ProtocolIPv6ICMP = 58
)
var Info *log.Logger
type EIPs struct {
	ipv4Addr   net.IPAddr
	ipv6Addr   net.IPAddr
	ipv4Status bool
	ipv6Status bool
}

type Checker struct {
	Id      int
	Seq     int
	Size    int
	Addrs   map[string]*EIPs
	Source  string
	TimeOut time.Duration
	OnRecv  func(*net.IPAddr, time.Duration)
	OnIdle  func()
	Mutex   *sync.Mutex
}

type Packet struct {
	bytes []byte
	addr  net.Addr
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func isIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len
}

func ipv4Payload(b []byte) []byte {
	if len(b) < ipv4.HeaderLen {
		return b
	}
	hdrLen := int(b[0]&0x0f) << 2
	return b[hdrLen:]
}

func bytesToTime(b []byte) time.Time {
	var nSec int64
	for i := uint8(0); i < 8; i++ {
		nSec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nSec/1000000000, nSec%1000000000)
}

func timeToBytes(t time.Time) []byte {
	nSec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nSec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

func byteSliceOfSize(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < len(b); i++ {
		b[i] = 1
	}
	return b
}

func NewChecker() *Checker {
	rand.Seed(time.Now().UnixNano())
	return &Checker{
		Id:      rand.Intn(0xffff),
		Seq:     rand.Intn(0xffff),
		Addrs:   make(map[string]*EIPs),
		Source:  "",
		Size:    TimeSliceLength,
		TimeOut: 5 * time.Second,
		OnRecv:  nil,
		OnIdle:  nil,
		Mutex:   &sync.Mutex{},
	}
}

func (c *Checker) AddEIPs(id, ipv4, ipv6 string) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	c.Addrs[id] = &EIPs{
		ipv4Addr:   net.IPAddr{IP: net.ParseIP(ipv4)},
		ipv6Addr:   net.IPAddr{IP: net.ParseIP(ipv6)},
		ipv4Status: false,
		ipv6Status: false,
	}
	Info.Printf("* %-92s *\n", fmt.Sprintf("Add IPv4 = %-15s IPv6 = %-40s", ipv4, ipv6))
}

func (c *Checker) RemoveEIPs(ipv4, ipv6 string) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	var key string
	for k, v := range c.Addrs {
		if ipv4 == v.ipv4Addr.IP.String() && ipv6 == v.ipv6Addr.IP.String() {
			key = k
			break
		}
	}

	delete(c.Addrs, key)
}

func (c *Checker) Run() error {
	var conn4, conn6 *icmp.PacketConn
	var err4, err6 error

	if conn4, err4 = icmp.ListenPacket("ip4:icmp", c.Source); err4 != nil {
		return err4
	}
	if conn6, err6 = icmp.ListenPacket("ip6:ipv6-icmp", c.Source); err6 != nil {
		return err6
	}
	defer conn4.Close()
	defer conn6.Close()

	recv := make(chan *Packet, 1)
	wg := new(sync.WaitGroup)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.recvICMP(ctx, conn4, conn6, recv, wg)
	if err := c.sendICMP(conn4, conn6); err != nil {
		return err
	}
	timer := time.NewTimer(c.TimeOut)
LOOP:
	for {
		select {
		case <-timer.C:
			handler := c.OnIdle
			if handler != nil {
				handler()
			}
			cancel()
			break LOOP
		case r := <-recv:
			c.procRecv(r)
		}
	}
	wg.Wait()
	close(recv)
	return nil
}

func (c *Checker) recvICMP(ctx context.Context, conn4, conn6 *icmp.PacketConn, recv chan<- *Packet, wg *sync.WaitGroup) {
	wg.Add(1)
	go c.recvPacket(ctx, conn4, recv, wg)
	wg.Add(1)
	go c.recvPacket(ctx, conn6, recv, wg)
}

func (c *Checker) sendICMP(conn4, conn6 *icmp.PacketConn) error {
	wg := new(sync.WaitGroup)
	for _, addr := range c.Addrs {
		data := timeToBytes(time.Now())
		if l := c.Size - TimeSliceLength; l != 0 {
			data = append(data, byteSliceOfSize(l)...)
		}

		message4, err4 := (&icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID: c.Id, Seq: c.Seq,
				Data: data,
			},
		}).Marshal(nil)

		message6, err6 := (&icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest, Code: 0,
			Body: &icmp.Echo{
				ID: c.Id, Seq: c.Seq,
				Data: data,
			},
		}).Marshal(nil)

		if err4 != nil {
			wg.Wait()
			return err4
		}

		if err6 != nil {
			wg.Wait()
			return err6
		}

		wg.Add(2)
		go sendPacket(conn4, &addr.ipv4Addr, message4, wg)
		go sendPacket(conn6, &addr.ipv6Addr, message6, wg)
	}
	wg.Wait()
	return nil
}

func sendPacket(conn *icmp.PacketConn, dst net.Addr, bytes []byte, wg *sync.WaitGroup) {
	for {
		if _, err := conn.WriteTo(bytes, dst); err != nil {
			if netErr, ok := err.(*net.OpError); ok {
				if netErr.Err == syscall.ENOBUFS {
					continue
				}
			}
		}
		break
	}
	wg.Done()
}

func (c *Checker) recvPacket(ctx context.Context, conn *icmp.PacketConn, recv chan<- *Packet, wg *sync.WaitGroup) {
	for {
		select {
		case <-ctx.Done():
			wg.Done()
			return
		default:
		}

		bytes := make([]byte, 512)
		conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
		_, ra, err := conn.ReadFrom(bytes)
		if err != nil {
			if netErr, ok := err.(*net.OpError); ok {
				if netErr.Timeout() {
					continue
				}
			}
		}

		select {
		case recv <- &Packet{bytes: bytes, addr: ra}:
		case <-ctx.Done():
			wg.Done()
			return
		}
	}
}

func (c *Checker) procRecv(recv *Packet) {
	ipAddr := recv.addr.(*net.IPAddr)
	addr := ipAddr.String()
	var key string

	for k, v := range c.Addrs {
		if addr == v.ipv4Addr.IP.String() || addr == v.ipv4Addr.IP.String() {
			key = k
			break
		}
	}

	if key == "" {
		return
	}

	var bytes []byte
	var protocol int
	isV4 := isIPv4(ipAddr.IP)
	isV6 := isIPv6(ipAddr.IP)

	if isV4 {
		bytes = ipv4Payload(recv.bytes)
		protocol = ProtocolICMP
	} else if isV6 {
		bytes = recv.bytes
		protocol = ProtocolIPv6ICMP
	} else {
		return
	}

	var m *icmp.Message
	var err error
	if m, err = icmp.ParseMessage(protocol, bytes); err != nil {
		return
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		return
	}

	var rtt time.Duration
	switch pkt := m.Body.(type) {
	case *icmp.Echo:
		c.Mutex.Lock()
		if pkt.ID == c.Id && pkt.Seq == c.Seq {
			rtt = time.Since(bytesToTime(pkt.Data[:TimeSliceLength]))
		}
		c.Mutex.Unlock()
	default:
		return
	}

	if isV4 {
		c.Mutex.Lock()
		c.Addrs[key].ipv4Status = true
		c.Mutex.Unlock()
	} else if isV6 {
		c.Mutex.Lock()
		c.Addrs[key].ipv6Status = true
		c.Mutex.Unlock()
	} else {
		return
	}

	handler := c.OnRecv
	if handler != nil {
		handler(ipAddr, rtt)
	}
}

func getNAT64Info(ip string, port int) (*proto.GetNAT64Response, error) {
	conn, err := grpc.Dial(fmt.Sprintf("%s:%d", ip, port), grpc.WithInsecure())
	if err != nil {
		Info.Printf("Cannot connect to gRPC server = %s:%d, error = %v\n.", ip, port, err)
		return nil, err
	}
	defer conn.Close()
	c := proto.NewNAT64ServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r, err := c.GetNAT64(ctx, &proto.GetNAT64Request{})
	return r, err
}

func initLog(enable bool) {
	if enable {
		errFile, err := os.OpenFile("nat64.check.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Open log file failed, error = %v.\n", err)
		}
		Info = log.New(io.MultiWriter(os.Stdout, errFile), "", log.Ltime|log.Lshortfile)
	} else {
		Info = log.New(os.Stdout, "", log.Ltime|log.Lshortfile)
	}
}

func main() {
	addr := flag.String("ip", "172.18.182.43", "gRPC server ip address")
	port := flag.Int("port", 9001, "gRPC server port")
	timeout := flag.Int("timeout", 10, "Timeout in seconds")
	size := flag.Int("size", 8, "ICMP packet size")
	enable := flag.Bool("enable", true, "Enable output detailed info to specific log file")
	test := flag.Bool("test", false, "Enable hard code for test, only for test")
	flag.Parse()
	initLog(*enable)

	c := NewChecker()
	c.TimeOut = time.Duration(*timeout) * time.Second
	c.Size = *size

	if *test {
		c.AddEIPs("1", "117.50.23.225", "240e:83:201:4e00::7532:17e1")
		c.AddEIPs("2", "117.50.62.5", "240e:83:201:4e00::7532:3e05")
		c.AddEIPs("3", "106.75.99.20", "240e:83:201:4e00::6a4b:6314")
		c.AddEIPs("4", "117.50.37.144", "240e:83:201:4e00::7532:2590")
		c.AddEIPs("5", "106.75.13.29", "240e:83:201:4e00::6a4b:d1d")
		c.AddEIPs("6", "117.50.24.175", "240e:83:201:4e00::7532:18af")
		c.AddEIPs("7", "117.50.62.233", "240e:83:201:4e00::7532:3ee9")
		c.AddEIPs("8", "117.50.23.88", "240e:83:201:4e00::7532:1758")
		c.AddEIPs("9", "106.75.66.192", "240e:83:201:4e00::6a4b:42c0")
		c.AddEIPs("10", "117.50.65.92", "240e:83:201:4e00::7532:415c")
		c.AddEIPs("11", "106.75.76.186", "240e:83:201:4e00::6a4b:4cba")
		c.AddEIPs("12", "117.50.88.190", "240e:83:201:4e00::7532:58be")
		c.AddEIPs("13", "117.50.40.53", "240e:83:201:4e00::7532:2835")
		c.AddEIPs("14", "106.75.12.74", "240e:83:201:4e00::6a4b:c4a")
	} else {
		//如果获取EIP信息失败，直接退出
		r, err := getNAT64Info(*addr, *port)
		if err != nil || r.Retcode != 0 {
			Info.Printf("Get NAT64 request failed, error = %v, retcode = %v.\n", err, r.Retcode)
			os.Exit(1)
		}

		for k, v := range r.Nat64S {
			//使能过nat转换的才进行检查，用id作为key存储到map
			if v.Enabled {
				c.AddEIPs(k, v.Eipv4, v.Eipv6)
			}
		}
	}

	//收到Reply报文的回调
	c.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
		s := fmt.Sprintf("Receive IP Addr: %-15s RTT: %v", addr.String(), rtt)
		Info.Printf("* %-92s *\n", s)
	}

	//检测的超时后的回调，输出结果
	c.OnIdle = func() {
		Info.Println("************************************************************************************************")
		Info.Println("*                                        NAT64 Check Results                                   *")
		Info.Println("************************************************************************************************")
		Info.Println("*----------------------------------------------------------------------------------------------*")

		if *test {
			Info.Printf("* %-92s *\n", "Hard code for test")
		} else {
			Info.Printf("* %-92s *\n", fmt.Sprintf("gRPC Server : %v:%v", *addr, *port))
			Info.Printf("* %-92s *\n", fmt.Sprintf("Timeout(s)  : %v", *timeout))
			Info.Printf("* %-92s *\n", fmt.Sprintf("Packet Size : %v", *size))
			Info.Printf("* %-92s *\n", fmt.Sprintf("Enable Log  : %v", *enable))
		}
		Info.Println("*----------------------------------------------------------------------------------------------*")

		m := map[bool]string{false: " Failed ", true: " OK "}
		c.Mutex.Lock()
		for _, v := range c.Addrs {
			s := fmt.Sprintf("IPv4 = %-15s [%-8s] IPv6 = %-40s [%-8s]",
				v.ipv4Addr.String(), m[v.ipv4Status],
				v.ipv6Addr.String(), m[v.ipv6Status])
			Info.Printf("* %-92s *\n", s)
		}
		c.Mutex.Unlock()
		Info.Println("************************************************************************************************")
	}

	//开始检测，发送、接受ICMP报文
	if err := c.Run(); err != nil {
		Info.Printf("Nat64 check failed, error = %v\n", err)
	}
}
