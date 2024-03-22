package fritzbox

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
	upnp "github.com/sberk42/fritzbox_exporter/fritzbox_upnp"
	"github.com/sirupsen/logrus"
)

var (
	wanIPConnectionServiceURN   string = "urn:schemas-upnp-org:service:WANIPConnection:1"
	getExternalIPv4Action       string = "GetExternalIPAddress"
	getExternalIPv6Action       string = "X_AVM_DE_GetExternalIPv6Address"
	getExternalIPv6PrefixAction string = "X_AVM_DE_GetIPv6Prefix"
)

type ExternalIPv6 struct {
	IPv6Address      string `mapstructure:"ExternalIPv6Address"`
	PreferedLifetime int    `mapstructure:"PreferedLifetime"`
	PrefixLength     int    `mapstructure:"PrefixLength"`
	ValidLifetime    int    `mapstructure:"ValidLifetime"`
}

type ExternalIPv6Prefix struct {
	IPv6Prefix       string `mapstructure:"IPv6Prefix"`
	PreferedLifetime int    `mapstructure:"PreferedLifetime"`
	PrefixLength     int    `mapstructure:"PrefixLength"`
	ValidLifetime    int    `mapstructure:"ValidLifetime"`
}

type ExternalIPv4 struct {
	IPv4Address string `mapstructure:"ExternalIPAddress"`
}

func NewUPNPClient(url, username, password string, verifyTLS bool) UPNPClient {
	return &upnpClient{url: url, username: username, password: password, verifyTLS: verifyTLS}
}

type UPNPClient interface {
	GetExternalIPv4Address() (*ExternalIPv4, error)
	GetExternalIPv6Address() (*ExternalIPv6, error)
	GetExternalIPv6Prefix() (*ExternalIPv6Prefix, error)
}

type upnpClient struct {
	url       string
	username  string
	password  string
	verifyTLS bool
}

// GetExternalIPv4Address implements UPNPClient.
func (u *upnpClient) GetExternalIPv4Address() (*ExternalIPv4, error) {
	svc, err := u.getService(wanIPConnectionServiceURN)
	if err != nil {
		return nil, fmt.Errorf("error getting service: %w", err)
	}
	action, ok := svc.Actions[getExternalIPv4Action]
	if !ok {
		return nil, fmt.Errorf("could not find action %q", getExternalIPv4Action)
	}
	data, err := action.Call(nil)
	if err != nil {
		return nil, fmt.Errorf("could not execute action: %w", err)
	}
	logrus.Debugf("Got data: %v", data)
	var ipv4 ExternalIPv4
	if err := mapstructure.Decode(data, &ipv4); err != nil {
		return nil, fmt.Errorf("could not extract external IPv4 address: %w", err)
	}
	return &ipv4, nil
}

// GetExternalIPv6Address implements UPNPClient.
func (u *upnpClient) GetExternalIPv6Address() (*ExternalIPv6, error) {
	svc, err := u.getService(wanIPConnectionServiceURN)
	if err != nil {
		return nil, fmt.Errorf("error getting service: %w", err)
	}
	action, ok := svc.Actions[getExternalIPv6Action]
	if !ok {
		return nil, fmt.Errorf("could not find action %q", getExternalIPv6Action)
	}
	data, err := action.Call(nil)
	if err != nil {
		return nil, fmt.Errorf("could not execute action: %w", err)
	}
	logrus.Debugf("Got data: %v", data)
	var ipv6 ExternalIPv6
	if err := mapstructure.Decode(data, &ipv6); err != nil {
		return nil, fmt.Errorf("could not extract external IPv6 address: %w", err)
	}
	return &ipv6, nil
}

// GetExternalIPv6Prefix implements UPNPClient.
func (u *upnpClient) GetExternalIPv6Prefix() (*ExternalIPv6Prefix, error) {
	svc, err := u.getService(wanIPConnectionServiceURN)
	if err != nil {
		return nil, fmt.Errorf("error getting service: %w", err)
	}
	action, ok := svc.Actions[getExternalIPv6PrefixAction]
	if !ok {
		return nil, fmt.Errorf("could not find action %q", getExternalIPv6PrefixAction)
	}
	data, err := action.Call(nil)
	if err != nil {
		return nil, fmt.Errorf("could not execute action: %w", err)
	}
	logrus.Debugf("Got data: %v", data)
	var ipv6Prefix ExternalIPv6Prefix
	if err := mapstructure.Decode(data, &ipv6Prefix); err != nil {
		return nil, fmt.Errorf("could not extract external IPv6 prefix: %w", err)
	}
	return &ipv6Prefix, nil
}

func (u *upnpClient) getService(svc string) (*upnp.Service, error) {
	root, err := upnp.LoadServices(u.url, u.username, u.password, u.verifyTLS)
	if err != nil {
		return nil, fmt.Errorf("cannot load services: %w", err)
	}
	logrus.Debugf("Device: %+#v", root.Device)
	for svcName := range root.Services {
		logrus.Debugf("Available service: %s", svcName)
	}
	logrus.Infof("Getting service %q", svc)
	service, ok := root.Services[svc]
	if !ok {
		return nil, fmt.Errorf("could not find service %q", svc)
	}
	for actionName := range service.Actions {
		logrus.Debugf("Available actions: %s", actionName)
	}
	return service, nil
}
