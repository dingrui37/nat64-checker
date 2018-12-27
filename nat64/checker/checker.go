package main

import (
	"context"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"log"
	"math/rand"
	"nat64/proto"
	"net"
	"sync"
	"syscall"
	"time"
)

const (
	TimeSliceLength  = 8
	ProtocolICMP     = 1
	ProtocolIPv6ICMP = 58
)

type IPInfo struct {
	IpAddr   net.IPAddr
	IpStatus bool
	IpRtt    time.Duration
}

type EIPs struct {
	Ipv4Info IPInfo
	Ipv6Info IPInfo
}

type Checker struct {
	Id      int
	Seq     int
	Size    int
	Addrs   map[string]*EIPs
	Source  string
	TimeOut time.Duration
	Mutex   *sync.Mutex
	Zone    string
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

func status2Str(status bool) (result string) {
	m := map[bool]string{false: " Failed ", true: " SUCCESS "}
	result = m[status]
	return result
}

func rtt2Str(rtt time.Duration) (result string) {
	if rtt == -1 {
		result = "N/A"
	} else {
		result = fmt.Sprintf("%v", rtt)
	}
	return
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
		Mutex:   &sync.Mutex{},
	}
}

func (c *Checker) AddEIPs(id, ipv4, ipv6 string) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()

	if ipv4 != "" && ipv6 != "" {
		c.Addrs[id] = &EIPs{
			Ipv4Info: IPInfo{IpAddr: net.IPAddr{IP: net.ParseIP(ipv4)}, IpStatus: false, IpRtt: -1},
			Ipv6Info: IPInfo{IpAddr: net.IPAddr{IP: net.ParseIP(ipv6)}, IpStatus: false, IpRtt: -1},
		}
	}
}

func (c *Checker) RemoveEIPs(ipv4, ipv6 string) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	var key string
	for k, v := range c.Addrs {
		if ipv4 == v.Ipv4Info.IpAddr.IP.String() && ipv6 == v.Ipv6Info.IpAddr.IP.String() {
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

	wg := new(sync.WaitGroup)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.recvICMP(ctx, conn4, conn6, wg)

	//如果发包失败，那么本次检测就毫无意义了，cancel收包goroutine
	if err := c.sendICMP(conn4, conn6); err != nil {
		cancel()
		wg.Wait()
		return err
	}

	timer := time.NewTimer(c.TimeOut)
LOOP:
	for {
		select {
		case <-timer.C:
			cancel()
			c.onTimeOut()
			break LOOP
		default:
		}
	}
	wg.Wait()
	return nil
}

func (c *Checker) dataLocalization(in *proto.SetNAT64Request) {
	Debugln("Localize data start.")

	//判断gRPC返回结果
	if in.Request.Retcode != 0 {
		return
	}

	//过滤使能过NAT转换的,过滤脏数据
	for k, v := range in.Request.Nat64S {
		if v.Enabled {
			if v.Eipv4 != "" && v.Eipv6 != "" {
				c.Addrs[k] = &EIPs{
					Ipv4Info: IPInfo{IpAddr: net.IPAddr{IP: net.ParseIP(v.Eipv4)}, IpStatus: false, IpRtt: -1},
					Ipv6Info: IPInfo{IpAddr: net.IPAddr{IP: net.ParseIP(v.Eipv6)}, IpStatus: false, IpRtt: -1},
				}
				Debugln("Add ", v.Eipv4, v.Eipv6)
			}
		}
	}
	c.Zone = in.Zone
	Debugln("Localize data end.")
}

func (c *Checker) recvICMP(ctx context.Context, conn4, conn6 *icmp.PacketConn, wg *sync.WaitGroup) {
	wg.Add(1)
	go c.recvPacket(ctx, conn4, wg)
	wg.Add(1)
	go c.recvPacket(ctx, conn6, wg)
}

func (c *Checker) sendICMP(conn4, conn6 *icmp.PacketConn) error {
	wg := new(sync.WaitGroup)
	c.Mutex.Lock()

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
		go sendPacket(conn4, &addr.Ipv4Info.IpAddr, message4, wg)
		go sendPacket(conn6, &addr.Ipv6Info.IpAddr, message6, wg)
	}
	c.Mutex.Unlock()
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
		Debugln("send packet success = ", dst)
		break
	}
	wg.Done()
}

func (c *Checker) recvPacket(ctx context.Context, conn *icmp.PacketConn, wg *sync.WaitGroup) {
	for {
		select {
		case <-ctx.Done():
			wg.Done()
			return
		default:
		}

		bytes := make([]byte, 512)
		conn.SetReadDeadline(time.Now().Add(time.Millisecond))
		_, ra, err := conn.ReadFrom(bytes)
		if err != nil {
			if netErr, ok := err.(*net.OpError); ok {
				if netErr.Timeout() {
					continue
				}
			}
		}
		Debugln("receive packet , addr = ", ra)
		c.procRecv(&Packet{bytes: bytes, addr: ra})
	}
}

func (c *Checker) procRecv(recv *Packet) {
	Debugln("Process packet start , addr = ", recv.addr)
	ipAddr := recv.addr.(*net.IPAddr)
	addr := ipAddr.String()
	var key string

	c.Mutex.Lock()
	for k, v := range c.Addrs {
		if addr == v.Ipv4Info.IpAddr.String() || addr == v.Ipv6Info.IpAddr.IP.String() {
			key = k
			break
		}
	}
	c.Mutex.Unlock()
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
		log.Println("other ipv? packet")
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
		} else {
			Debugln("Not my icmp reply packet")
		}
		c.Mutex.Unlock()
	default:
		Debugln("Not icmp reply packet")
		return
	}

	c.Mutex.Lock()
	if isV4 {
		c.Addrs[key].Ipv4Info.IpStatus = true
		c.Addrs[key].Ipv4Info.IpRtt = rtt
	} else if isV6 {
		c.Addrs[key].Ipv6Info.IpStatus = true
		c.Addrs[key].Ipv6Info.IpRtt = rtt
	} else {
		return
	}
	c.Mutex.Unlock()
	c.onRecv(ipAddr, rtt)
}

func (c *Checker) onRecv(addr *net.IPAddr, rtt time.Duration) {
	Debugf("Receive IP Addr: %-40s RTT: %v\n", addr.String(), rtt)
}

func (c *Checker) onTimeOut() {
	LOG.Println("*********************************************************************************")
	LOG.Println("*                               NAT64 CHECK RESULTS                             *")
	LOG.Println("*********************************************************************************")
	LOG.Println("* ----------------------------------------------------------------------------- *")
	result := "SUCCESS"
	failedCount := 0
	c.Mutex.Lock()
	for _, v := range c.Addrs {
		ipv4RttStr := rtt2Str(v.Ipv4Info.IpRtt)
		ipv6RttStr := rtt2Str(v.Ipv6Info.IpRtt)
		ipv4StatusStr := status2Str(v.Ipv4Info.IpStatus)
		ipv6StatusStr := status2Str(v.Ipv6Info.IpStatus)
		ipv4IpStr := v.Ipv4Info.IpAddr.String()
		ipv6IpStr := v.Ipv6Info.IpAddr.String()

		//任何一个IPv4通，IPv6不通，本次检测最终结果认为失败
		if v.Ipv4Info.IpStatus && !v.Ipv6Info.IpStatus {
			result = "FAILED"
			failedCount = failedCount + 1
		}

		//任何一个IPv4不通，但是IPv6通，理论上不可能，
		if !v.Ipv4Info.IpStatus && v.Ipv6Info.IpStatus {
			result = "FAILED"
			failedCount = failedCount + 1
		}

		LOG.Printf("* IPv4 = %-40s [%-10s][ %-12s ]  *\n", ipv4IpStr, ipv4StatusStr, ipv4RttStr)
		LOG.Printf("* IPv6 = %-40s [%-10s][ %-12s ]  *\n", ipv6IpStr, ipv6StatusStr, ipv6RttStr)
		LOG.Printf("* ----------------------------------------------------------------------------- *\n")
	}
	c.Mutex.Unlock()
	r := fmt.Sprintf("Result : %s [%v/%v]", result, failedCount, len(c.Addrs))
	d := fmt.Sprintf("Date   : %v", time.Now())
	z := fmt.Sprintf("Zone   : %v", c.Zone)
	LOG.Printf("* %-77s *\n", r)
	LOG.Printf("* %-77s *\n", d)
	LOG.Printf("* %-77s *\n", z)
	LOG.Println("* ----------------------------------------------------------------------------- *")
	LOG.Println("*********************************************************************************")
}
