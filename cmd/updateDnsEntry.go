/*
Copyright © 2024 Michael Wagner <mitch.wagna@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"

	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/ddns"
	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/ip"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// updateDnsEntryCmd represents the updateDnsEntry command
var updateDnsEntryCmd = &cobra.Command{
	Use:   "updateDnsEntry [flags] ips",
	Short: "Update dyndns entries using the specified IPs",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		ipArgs, err := parseIPArgs(args)
		if err != nil {
			logrus.Errorf("error parsing IPs: %v", err)
			os.Exit(1)
		}
		provider := provider.ProviderFactory()(ddns.UsernamePasswordCredentials(
			providerUsername, providerPassword,
		))
		ipsToUpdate := ipArgs
		if checkIfUpdateIsNeeded {
			logrus.Infof("Get DNS records for %q", dnsNameFlag)
			resolver := net.Resolver{}
			dnsIPs, err := resolveDNSEntry(cmd.Context(), &resolver, dnsNameFlag)
			if err != nil {
				logrus.Errorf("Error looking up dns name %q: %v", dnsNameFlag, err)
			}
			result := compareCIDRS(ipsToUpdate, dnsIPs)
			if result == 0 {
				logrus.Infof("Records for %q already match the actual IPs", dnsNameFlag)
				os.Exit(0)
				return
			}
		}
		logrus.Infof("Updating dns name %q with IPs %v using %s\n", dnsNameFlag, ipsToUpdate, provider.Name())
		if err := provider.UpdateRecord(context.Background(), dnsNameFlag, ipsToUpdate...); err != nil {
			logrus.Errorf("Updating the records failed: %v", err)
			os.Exit(1)
		}
	},
}

func parseIPArgs(args []string) ([]ip.CIDR, error) {
	var cidrs []ip.CIDR
	for i, arg := range args {
		addr, err := netip.ParseAddr(arg)
		if err != nil {
			return nil, fmt.Errorf("error parsing IP address from arg %d: %w", i+1, err)
		}
		if addr.Is6() {
			cidrs = append(cidrs, ip.CIDR{
				Prefix:       netip.PrefixFrom(addr, 128),
				PrefixLength: 128,
			})
			continue
		}
		cidrs = append(cidrs, ip.CIDR{
			Prefix:       netip.PrefixFrom(addr, 32),
			PrefixLength: 32,
		})
	}
	return cidrs, nil
}

var (
	provider              DDNSProvider
	providerUsername      string
	providerPassword      string
	dnsNameFlag           string
	checkIfUpdateIsNeeded bool
)

type DDNSProvider struct {
	name string
}

func (d *DDNSProvider) ProviderFactory() ddns.ProviderFactory {
	switch provider.name {
	case "noip":
		return ddns.NewNoIPProvider
	default:
		panic("unreachable")
	}
}

// Set implements pflag.Value.
func (d *DDNSProvider) Set(v string) error {
	if !slices.Contains(ddns.AvailableProviders, v) {
		return fmt.Errorf("provider not supported: %q", v)
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

func init() {
	rootCmd.AddCommand(updateDnsEntryCmd)
	updateDnsEntryCmd.Flags().Var(
		&provider, "provider",
		fmt.Sprintf("the DDNS provider to use. Availabe providers are %v", ddns.AvailableProviders),
	)
	updateDnsEntryCmd.Flags().StringVar(&providerUsername, "provider.username", "", "the ddns provider username")
	updateDnsEntryCmd.Flags().StringVar(&providerPassword, "provider.password", "", "the ddns provider password")
	updateDnsEntryCmd.Flags().StringVar(&dnsNameFlag, "dns-name", "", "the ddns domain to update")
	updateDnsEntryCmd.Flags().BoolVar(&checkIfUpdateIsNeeded, "check-if-needed", false, "check via DNS resolution if the entries needs an update")
}
