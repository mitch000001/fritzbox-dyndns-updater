package ddns

import "github.com/mitch000001/fritzbox-dyndns-updater/pkg/ip"

var AvailableProviders = []string{}

type Provider interface {
	UpdateRecord(dnsName string, ips ...ip.IP) error
	Name() string
	SupportsIPv6PrefixUpdate() bool
}

func UsernamePasswordCredentials(username, password string) ProviderCredentials {
	return ProviderCredentials{
		username: username,
		password: password,
	}
}

type ProviderCredentials struct {
	username string
	password string
}

type ProviderFactory func(creds ProviderCredentials) Provider
