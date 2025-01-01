package ddns

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/ip"
	"github.com/sirupsen/logrus"
)

func init() {
	registerProvider(providerNameSelfhostDe, NewSelfhostDeProvider)
}

const providerNameSelfhostDe = "selfhost.de"
const throttleTimeoutSelfhostDe = 10 * time.Second

func NewSelfhostDeProvider(creds ProviderCredentials) Provider {
	return &selfhostDeProvider{
		username: creds.username,
		password: creds.password,
	}
}

type selfhostDeProvider struct {
	username string
	password string
}

// SupportsIPv6PrefixUpdate implements Provider.
func (n *selfhostDeProvider) SupportsIPv6PrefixUpdate() bool {
	return true
}

// Name implements Provider.
func (n *selfhostDeProvider) Name() string {
	return providerNameSelfhostDe
}

// UpdateRecord implements Provider.
func (n *selfhostDeProvider) UpdateRecord(ctx context.Context, dnsName string, ipAddresses ...ip.CIDR) error {
	var ips []string
	for _, ipCidr := range ipAddresses {
		if ipCidr.IsPrefix {
			ips = append(ips, ipCidr.Prefix.String())
			continue
		}
		ips = append(ips, ipCidr.Prefix.Addr().String())
	}

	for _, ip := range ips {
		if err := n.updateRecordWithIP(ctx, dnsName, ip); err != nil {
			logrus.Errorf("error updating record for IP %q: %v", ip, err)
		}
		time.Sleep(throttleTimeoutSelfhostDe)
	}
	return nil
}

func (n *selfhostDeProvider) updateRecordWithIP(ctx context.Context, dnsName string, ipOrIPv6Prefix string) error {
	query := url.Values{}
	query.Add("hostname", dnsName)
	query.Add("myip", ipOrIPv6Prefix)
	uri, err := url.Parse("https://carol.selfhost.de/nic/update?" + query.Encode())
	if err != nil {
		logrus.Errorf("error creating uri for request for selfhost.de: %v", err)
		os.Exit(1)
	}

	logrus.Debugf("uri: %v", uri)
	req, err := http.NewRequestWithContext(ctx, "GET", uri.String(), nil)
	if err != nil {
		return fmt.Errorf("error creating request for selfhost.de: %v", err)
	}
	req.SetBasicAuth(n.username, n.password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request to selfhost.de: %v", err)
	}
	logrus.Debugf("Response: %v\n", res)
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("error reading result from selfhost.de: %v", err)
	}
	logrus.Infof("selfhost.de response: %s\n", string(b))
	return nil
}
