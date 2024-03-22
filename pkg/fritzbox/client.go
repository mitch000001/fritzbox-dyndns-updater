package fritzbox

import (
	"fmt"
	"net"

	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/ip"
	"github.com/sirupsen/logrus"
)

type ClientCredentials struct {
	Username  string
	Password  string
	VerifyTLS bool
}

type Client interface {
	GetPublicIPs() ([]ip.IP, error)
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
func (c *client) GetPublicIPs() ([]ip.IP, error) {
	var ips []ip.IP
	logrus.Infoln("Getting external IPv6 address")
	externalIPv6, err := c.UPNPClient.GetExternalIPv6Address()
	if err != nil {
		return nil, fmt.Errorf("could not get external IPv6 address: %v", err)
	}
	logrus.Debugf("Got external IPv6 address: %v", externalIPv6)
	extIpv6IP, extIpv6Net, err := net.ParseCIDR(
		fmt.Sprintf("%s/%d", externalIPv6.IPv6Address, externalIPv6.PrefixLength),
	)
	if err != nil {
		return nil, fmt.Errorf("error parsing external IPv6 CIDR: %w", err)
	}
	ips = append(ips, ip.IP{
		IP:  extIpv6IP,
		Net: *extIpv6Net,
	})
	logrus.Infoln("Getting external IPv6 prefix")
	externalIPv6Prefix, err := c.UPNPClient.GetExternalIPv6Prefix()
	if err != nil {
		return nil, fmt.Errorf("could not get external IPv6 prefix: %w", err)
	}
	logrus.Debugf("Got external IPv6 prefix: %v", externalIPv6Prefix)
	extIpv6PrefixIP, extIpv6PrefixNet, err := net.ParseCIDR(
		fmt.Sprintf("%s/%d", externalIPv6Prefix.IPv6Prefix, externalIPv6Prefix.PrefixLength),
	)
	if err != nil {
		return nil, fmt.Errorf("error parsing external IPv6 Prefix CIDR: %w", err)
	}
	ips = append(ips, ip.IP{
		IP:       extIpv6PrefixIP,
		Net:      *extIpv6PrefixNet,
		IsPrefix: true,
	})
	logrus.Infoln("Getting external IPv4 address")
	externalIPv4, err := c.UPNPClient.GetExternalIPv4Address()
	if err != nil {
		return nil, fmt.Errorf("could not get external IPv6 prefix: %w", err)
	}
	logrus.Debugf("Got external IPv4 address: %v", externalIPv4)
	extIpv4IP, extIpv4Net, err := net.ParseCIDR(
		fmt.Sprintf("%s/32", externalIPv4.IPv4Address),
	)
	if err != nil {
		return nil, fmt.Errorf("error parsing external IPv6 CIDR: %w", err)
	}
	ips = append(ips, ip.IP{
		IP:  extIpv4IP,
		Net: *extIpv4Net,
	})
	return ips, nil
}
