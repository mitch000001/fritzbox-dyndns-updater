package ip

import "net"

type IP struct {
	IP       net.IP
	Net      net.IPNet
	IsPrefix bool
}
