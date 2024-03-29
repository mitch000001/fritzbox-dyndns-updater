package fritzbox

import (
	"fmt"
	"net/netip"

	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/ip"
	"github.com/sirupsen/logrus"
)

type ClientCredentials struct {
	Username  string
	Password  string
	VerifyTLS bool
}

type Client interface {
	GetPublicIPs(withIPv6Prefix bool) ([]ip.CIDR, error)
}

func NewClient(url string, creds ClientCredentials) (Client, error) {
	upnpClient := NewUPNPClient(url, creds)
	return &client{
		UPNPClient: upnpClient,
	}, nil
}

type client struct {
	UPNPClient
}

// GetPublicIPs implements Client.
func (c *client) GetPublicIPs(withIPv6Prefix bool) ([]ip.CIDR, error) {
	var cidrs []ip.CIDR
	logrus.Infoln("Getting external IPv6 address")
	externalIPv6, err := c.UPNPClient.GetExternalIPv6Address()
	if err != nil {
		return nil, fmt.Errorf("could not get external IPv6 address: %v", err)
	}
	logrus.Debugf("Got external IPv6 address: %v", externalIPv6)
	extIpv6Addr, err := netip.ParseAddr(
		externalIPv6.IPv6Address,
	)
	if err != nil {
		return nil, fmt.Errorf("error parsing external IPv6 Address: %w", err)
	}
	extIpv6Prefix := netip.PrefixFrom(
		extIpv6Addr, externalIPv6.PrefixLength,
	)
	cidrs = append(cidrs, ip.CIDR{
		Prefix:           extIpv6Prefix,
		PreferedLifetime: externalIPv6.PreferedLifetime,
		ValidLifetime:    externalIPv6.ValidLifetime,
		PrefixLength:     externalIPv6.PrefixLength,
	})
	if withIPv6Prefix {
		logrus.Infoln("Getting external IPv6 prefix")
		externalIPv6Prefix, err := c.UPNPClient.GetExternalIPv6Prefix()
		if err != nil {
			return nil, fmt.Errorf("could not get external IPv6 prefix: %w", err)
		}
		logrus.Debugf("Got external IPv6 prefix: %v", externalIPv6Prefix)
		extIpv6PrefixAddr, err := netip.ParseAddr(
			externalIPv6.IPv6Address,
		)
		if err != nil {
			return nil, fmt.Errorf("error parsing external IPv6 prefix: %w", err)
		}
		cidrs = append(cidrs, ip.CIDR{
			Prefix: netip.PrefixFrom(
				extIpv6PrefixAddr, externalIPv6Prefix.PrefixLength,
			),
			PreferedLifetime: externalIPv6Prefix.PreferedLifetime,
			ValidLifetime:    externalIPv6Prefix.ValidLifetime,
			PrefixLength:     externalIPv6Prefix.PrefixLength,
			IsPrefix:         true,
		})
	}
	logrus.Infoln("Getting external IPv4 address")
	externalIPv4, err := c.UPNPClient.GetExternalIPv4Address()
	if err != nil {
		return nil, fmt.Errorf("could not get external IPv6 prefix: %w", err)
	}
	logrus.Debugf("Got external IPv4 address: %v", externalIPv4)
	extIpv4Addr, err := netip.ParseAddr(
		externalIPv4.IPv4Address,
	)
	if err != nil {
		return nil, fmt.Errorf("error parsing external IPv4 Address: %w", err)
	}
	cidrs = append(cidrs, ip.CIDR{
		Prefix: netip.PrefixFrom(extIpv4Addr, 32),
	})
	return cidrs, nil
}
