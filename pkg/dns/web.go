package dns

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/ip"
	"github.com/sirupsen/logrus"
)

func NewWebResolver(cfg WebResolverConfig) Resolver {
	return &webResolver{
		config: &cfg,
	}
}

var defaultWebResolverURL = url.URL{Scheme: "https", Host: "icanhazip.com"}

type WebResolverConfig struct {
	HTTPClient *http.Client
	URL        *url.URL
}

type webResolver struct {
	config *WebResolverConfig
}

func (w *webResolver) GetPublicIPs(ctx context.Context) ([]ip.CIDR, error) {
	w.init()
	var ips []ip.CIDR
	logrus.Infoln("Getting default external IP address")
	publicIP, err := w.getPublicIP(ctx, w.config.HTTPClient.Transport)
	if err != nil {
		return nil, fmt.Errorf("error getting public IP: %w", err)
	}
	ips = append(ips, *publicIP)
	if publicIP.Prefix.Addr().Is4() {
		logrus.Debugf("Got external IPv4 address: %v", publicIP)
		ipv6, err := w.getPublicIPv6(ctx)
		opErr := &net.OpError{}
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			logrus.Infof("Unable to get IPv6 address: %v", err)
			return ips, nil
		}
		if err != nil {
			return nil, fmt.Errorf("error getting IPv6 address: %w", err)
		}
		ips = append(ips, *ipv6)
		logrus.Debugf("Got external IPv6 address: %v", ipv6)
		return ips, nil
	}
	if publicIP.Prefix.Addr().Is6() {
		logrus.Debugf("Got external IPv6 address: %v", publicIP)
		ipv4, err := w.getPublicIPv4(ctx)
		opErr := &net.OpError{}
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			logrus.Infof("Unable to get IPv4 address: %v", err)
			return ips, nil
		}
		if err != nil {
			return nil, fmt.Errorf("error getting IPv4 address: %w", err)
		}
		ips = append(ips, *ipv4)
		logrus.Debugf("Got external IPv4 address: %v", ipv4)
		return ips, nil
	}

	return ips, nil
}

func (w *webResolver) getPublicIPv4(ctx context.Context) (*ip.CIDR, error) {
	logrus.Infoln("Getting external IPv4 address")
	v4Transport := http.DefaultTransport.(*http.Transport).Clone()
	v4Transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return http.DefaultTransport.(*http.Transport).DialContext(ctx, "tcp4", addr)
	}
	return w.getPublicIP(ctx, v4Transport)
}

func (w *webResolver) getPublicIPv6(ctx context.Context) (*ip.CIDR, error) {
	logrus.Infoln("Getting external IPv6 address")
	v6Transport := http.DefaultTransport.(*http.Transport).Clone()
	v6Transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return http.DefaultTransport.(*http.Transport).DialContext(ctx, "tcp6", addr)
	}
	return w.getPublicIP(ctx, v6Transport)
}

func (w *webResolver) getPublicIP(ctx context.Context, transport http.RoundTripper) (*ip.CIDR, error) {
	origTransport := w.config.HTTPClient.Transport
	defer func() {
		w.config.HTTPClient.Transport = origTransport
	}()
	w.config.HTTPClient.Transport = transport
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.config.URL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}
	req.Host = w.config.URL.Host
	res, err := w.config.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending HTTP request: %w", err)
	}
	bodyScanner := bufio.NewScanner(res.Body)
	bodyScanner.Split(bufio.ScanLines)
	bodyScanner.Scan()
	line := bodyScanner.Text()
	addr, err := netip.ParseAddr(line)
	if err != nil {
		return nil, fmt.Errorf("error parsing address from body: %w", err)
	}
	if addr.Is6() {
		return &ip.CIDR{
			Prefix:       netip.PrefixFrom(addr, 128),
			PrefixLength: 128,
		}, nil
	}
	return &ip.CIDR{
		Prefix:       netip.PrefixFrom(addr, 32),
		PrefixLength: 32,
	}, nil
}

func (w *webResolver) init() {
	if w.config.HTTPClient == nil {
		w.config.HTTPClient = &http.Client{
			Transport: http.DefaultTransport,
		}
	}
	if w.config.HTTPClient.Transport == nil {
		w.config.HTTPClient.Transport = http.DefaultTransport
	}
	if w.config.URL == nil {
		w.config.URL = &defaultWebResolverURL
	}
}
