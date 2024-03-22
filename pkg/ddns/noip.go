package ddns

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AvailableProviders = append(AvailableProviders, "noip")
}

func NewNoIPProvider(username, password string) Provider {
	return &noipProvider{
		username: username,
		password: password,
	}
}

type noipProvider struct {
	username string
	password string
}

// UpdateRecord implements Provider.
func (n *noipProvider) UpdateRecord(dnsName string, ips ...string) error {
	query := url.Values{}
	query.Add("hostname", dnsName)
	query.Add("myip", strings.Join(ips, ","))
	uri, err := url.Parse("https://dynupdate.no-ip.com/nic/update?" + query.Encode())
	if err != nil {
		logrus.Errorf("error creating uri for request for noip: %v", err)
		os.Exit(1)
	}

	logrus.Debugf("uri: %v", uri)
	req, err := http.NewRequest("GET", uri.String(), nil)
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
