package ddns

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/ip"
	"github.com/sirupsen/logrus"
)

func init() {
	registerProvider(providerNameNoIP, NewNoIPProvider)
}

const providerNameNoIP = "noip"

func NewNoIPProvider(creds ProviderCredentials) Provider {
	return &noipProvider{
		username: creds.username,
		password: creds.password,
	}
}

type noipProvider struct {
	username string
	password string
}

// SupportsIPv6PrefixUpdate implements Provider.
func (n *noipProvider) SupportsIPv6PrefixUpdate() bool {
	return false
}

// Name implements Provider.
func (n *noipProvider) Name() string {
	return providerNameNoIP
}

// UpdateRecord implements Provider.
func (n *noipProvider) UpdateRecord(ctx context.Context, dnsName string, ipAddresses ...ip.CIDR) error {
	var ips []string
	for _, ip := range ipAddresses {
		if ip.IsPrefix {
			continue
		}
		ips = append(ips, ip.Prefix.Addr().String())
	}
	query := url.Values{}
	query.Add("hostname", dnsName)
	query.Add("myip", strings.Join(ips, ","))
	uri, err := url.Parse("https://dynupdate.no-ip.com/nic/update?" + query.Encode())
	if err != nil {
		logrus.Errorf("error creating uri for request for noip: %v", err)
		os.Exit(1)
	}

	logrus.Debugf("uri: %v", uri)
	req, err := http.NewRequestWithContext(ctx, "GET", uri.String(), nil)
	if err != nil {
		return fmt.Errorf("error creating request for noip: %v", err)
	}
	req.SetBasicAuth(n.username, n.password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request to noip: %v", err)
	}
	logrus.Debugf("Response: %v\n", res)
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("error reading result from noip: %v", err)
	}
	logrus.Infof("NoIP response: %s\n", string(b))
	return nil
}
