package dns

import (
	"context"

	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/ip"
)

type Resolver interface {
	GetPublicIPs(context.Context) ([]ip.CIDR, error)
}
