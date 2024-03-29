package ip

import (
	"net/netip"
)

type CIDR struct {
	Prefix           netip.Prefix
	PreferedLifetime int
	PrefixLength     int
	ValidLifetime    int
	IsPrefix         bool
}
