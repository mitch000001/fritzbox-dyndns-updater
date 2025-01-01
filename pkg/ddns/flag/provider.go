package flag

import (
	"fmt"
	"slices"

	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/ddns"
)

type DDNSProvider struct {
	name string
}

func (d *DDNSProvider) ProviderFactory() ddns.ProviderFactory {
	return ddns.NewProviderFactory(d.name)
}

// Set implements pflag.Value.
func (d *DDNSProvider) Set(v string) error {
	availableProviders := ddns.AvailableProviders()
	if !slices.Contains(availableProviders, v) {
		return fmt.Errorf("provider not supported: %q. Supported providers: %v", v, availableProviders)
	}
	d.name = v
	return nil
}

// String implements pflag.Value.
func (d *DDNSProvider) String() string {
	return d.name
}

// Type implements pflag.Value.
func (d *DDNSProvider) Type() string {
	return "string"
}
