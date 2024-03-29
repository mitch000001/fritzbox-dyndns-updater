/*
Copyright © 2024 Michael Wagner

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
	"cmp"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/ddns"
	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/fritzbox"
	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/ip"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		creds := fritzbox.ClientCredentials{
			Username:  fritzboxUsername,
			Password:  fritzboxPassword,
			VerifyTLS: fritzboxVerifyTLS,
		}
		client, err := fritzbox.NewClient(fritzboxURL, creds)
		if err != nil {
			logrus.Errorf("error creating fritzbox client: %v", err)
		}
		provider := provider.ProviderFactory()(ddns.UsernamePasswordCredentials(
			providerUsername, providerPassword,
		))
		ctx := cmd.Context()
		err = updateRecords(ctx, client, provider, dnsNamesFlag)
		if runOnce {
			if err != nil {
				logrus.Errorf("error updating dnsName with fritzbox ips: %v", err)
				os.Exit(1)
			}
			os.Exit(0)
			return
		}

		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		done := make(chan bool, 1)

		go func() {
			sig := <-sigs
			fmt.Println()
			fmt.Println("Received signal", sig)
			done <- true
		}()
		ctx, cancel := context.WithCancel(ctx)
		for {
			select {
			case <-done:
				cancel()
				fmt.Println("exiting")
				return
			case <-time.Tick(syncEvery):
				if err := updateRecords(ctx, client, provider, dnsNamesFlag); err != nil {
					logrus.Errorf("error updating %v with fritzbox ips: %v", dnsNamesFlag, err)
				}
			}
		}
	},
}

func updateRecords(ctx context.Context, client fritzbox.Client, provider ddns.Provider, dnsNames []string) error {
	logrus.Infoln("Collect public IPs from fritzbox")
	fritzboxExternalIPs, err := client.GetPublicIPs(false)
	if err != nil {
		return fmt.Errorf("error getting public IPs: %w", err)
	}
	logrus.Debugf("Collected public IPs from fritzbox: %v", fritzboxExternalIPs)
	logrus.Infoln("Collect DNS records")
	resolver := net.Resolver{}
	var dnsResults = map[string][]ip.CIDR{}
	for _, entry := range dnsNames {
		logrus.Infof("Get DNS records for %q", entry)
		dnsIPs, err := resolveDNSEntry(ctx, &resolver, entry)
		if err != nil {
			logrus.Errorf("Error looking up dns name %q: %v", entry, err)
		}
		dnsResults[entry] = dnsIPs
		logrus.Debugf("Collected public IPs for %q: %v", entry, dnsResults)
	}
	for entry, ips := range dnsResults {
		result := compareCIDRS(ips, fritzboxExternalIPs)
		if result == 0 {
			logrus.Infof("Records for %q already match the actual IPs", entry)
			continue
		}
		logrus.Infof("Updating dns entry %q with IPs %v using %s\n", entry, fritzboxExternalIPs, provider.Name())
		if err := provider.UpdateRecord(ctx, entry, fritzboxExternalIPs...); err != nil {
			return fmt.Errorf("updating the records failed: %w", err)
		}
	}
	return nil
}

func resolveDNSEntry(ctx context.Context, resolver *net.Resolver, host string) ([]ip.CIDR, error) {
	res, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("error looking up dns host %q: %v", host, err)
	}
	var dnsIPs []ip.CIDR
	for _, ipAddr := range res {
		prefix, err := netip.ParsePrefix(ipAddr.String())
		if err != nil {
			return nil, fmt.Errorf("error parsing Address CIDR: %v", err)
		}
		dnsIPs = append(dnsIPs, ip.CIDR{
			Prefix:       prefix,
			PrefixLength: prefix.Bits(),
		})
	}
	return dnsIPs, nil
}

func compareCIDRS(i, j []ip.CIDR) int {
	slices.SortFunc(i, func(a, b ip.CIDR) int {
		return cmp.Compare(a.Prefix.String(), b.Prefix.String())
	})
	slices.SortFunc(j, func(a, b ip.CIDR) int {
		return cmp.Compare(a.Prefix.String(), b.Prefix.String())
	})
	return slices.CompareFunc(i, j, func(a, b ip.CIDR) int {
		return cmp.Compare(a.Prefix.String(), b.Prefix.String())
	})
}

var (
	syncEvery time.Duration
	runOnce   bool
)

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringArrayVar(&dnsNamesFlag, "dns-entries", []string{}, "specifies the dns entries to look up")
	serveCmd.Flags().StringVar(&fritzboxURL, "fritzbox.url", "http://fritz.box:49000", "specify the fritzbox endpoint")
	serveCmd.Flags().StringVar(&fritzboxUsername, "fritzbox.username", "", "specify the fritzbox user")
	serveCmd.Flags().StringVar(&fritzboxPassword, "fritzbox.password", "", "specify the fritzbox password")
	serveCmd.Flags().BoolVar(&fritzboxVerifyTLS, "fritzbox.verify-tls", false, "specify if the TLS certificate needs to be verified")
	serveCmd.Flags().Var(
		&provider, "provider",
		fmt.Sprintf("the DDNS provider to use. Availabe providers are %v", ddns.AvailableProviders),
	)
	serveCmd.Flags().StringVar(&providerUsername, "provider.username", "", "the ddns provider username")
	serveCmd.Flags().StringVar(&providerPassword, "provider.password", "", "the ddns provider password")
	serveCmd.Flags().DurationVar(&syncEvery, "sync-every", 1*time.Hour, "how often should the IPs be synced")
	serveCmd.Flags().BoolVar(&runOnce, "run-once", false, "run the update once and exit")
}
