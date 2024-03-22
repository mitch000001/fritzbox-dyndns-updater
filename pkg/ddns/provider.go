package ddns

var AvailableProviders = []string{}

type Provider interface {
	UpdateRecord(dnsName string, ips ...string) error
}
