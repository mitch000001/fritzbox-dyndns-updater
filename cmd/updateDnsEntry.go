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
	"fmt"
	"slices"

	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/ddns"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// updateDnsEntryCmd represents the updateDnsEntry command
var updateDnsEntryCmd = &cobra.Command{
	Use:   "updateDnsEntry",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		switch provider.name {
		case "noip":
			ipsToUpdate := []string{}
			if ipv4 != "" {
				ipsToUpdate = append(ipsToUpdate, ipv4)
			}
			if ipv6 != "" {
				ipsToUpdate = append(ipsToUpdate, ipv6)
			}
			logrus.Infof("Updating dns name %q with IPs %v using NoIP\n", dnsName, ipsToUpdate)
			provider := ddns.NewNoIPProvider(providerUsername, providerPassword)
			provider.UpdateRecord(dnsName, ipsToUpdate...)
		default:
			panic("unreachable")
		}
	},
}

var (
	provider         DDNSProvider
	providerUsername string
	providerPassword string
	dnsName          string
	ipv4             string
	ipv6             string
)

type DDNSProvider struct {
	name string
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
	updateDnsEntryCmd.Flags().StringVar(&ipv4, "ipv4", "", "the IPv4 adress to set")
	updateDnsEntryCmd.Flags().StringVar(&ipv6, "ipv6", "", "the IPv6 adress to set")
	updateDnsEntryCmd.Flags().StringVar(&dnsName, "dns-name", "", "the ddns domain to update")
	updateDnsEntryCmd.Flags().StringVar(&providerUsername, "provider.username", "", "the ddns provider username")
	updateDnsEntryCmd.Flags().StringVar(&providerPassword, "provider.password", "", "the ddns provider password")
}
