package ddns

import (
	"context"
	"fmt"

	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/ip"
)

var providerFactories = map[string]ProviderFactory{}

func registerProvider(name string, factory ProviderFactory) {
	providerFactories[name] = factory
}

func AvailableProviders() []string {
	providerNames := []string{}
	for k, _ := range providerFactories {
		providerNames = append(providerNames, k)
	}
	return providerNames
}

type Provider interface {
	UpdateRecord(ctx context.Context, dnsName string, ips ...ip.CIDR) error
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

func NewProviderFactory(provider string) ProviderFactory {
	factory, ok := providerFactories[provider]
	if !ok {
		panic(fmt.Errorf("unknown provider %q", provider))
	}
	return factory
}

type ProviderFactory func(creds ProviderCredentials) Provider
