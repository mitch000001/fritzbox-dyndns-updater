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
	"net/url"
	"os"

	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/dns"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var dnsWebResolverURL string

// getLocalPublicIpsCmd represents the getLocalPublicIpsCmd command
var getLocalPublicIpsCmd = &cobra.Command{
	Use:   "getLocalPublicIPs",
	Short: "Get public IPs used to reach the internet",
	Long: `This command uses a HTTP DNS resolver to check which IPs, either IPv4 or IPv6,
are used to access the internet.

There is the option to change the used website which should report bach the IPs using '--dns.resolverURL'. 
The expected return code of that service is just the IP(s) in plaintext. This command will do a lookup on 
either IPv4 and IPv6 to resolve both IPs if possible.
`,
	Run: func(cmd *cobra.Command, args []string) {
		uri, err := url.Parse(dnsWebResolverURL)
		if err != nil {
			uri = nil
		}

		resolver := dns.NewWebResolver(dns.WebResolverConfig{URL: uri})
		ips, err := resolver.GetPublicIPs(cmd.Context())
		if err != nil {
			logrus.Errorf("error getting public IPs: %v", err)
			os.Exit(1)
			return
		}
		logrus.Infof("Got external IP addresses: %d", len(ips))
		fmt.Println(stringifyIPs(ips, "\n"))
	},
}

func init() {
	rootCmd.AddCommand(getLocalPublicIpsCmd)

	getLocalPublicIpsCmd.Flags().StringVar(&dnsWebResolverURL, "dns.resolverURL", "https://icanhazip.com", "specifies the dns entry which can return the current public IPs.")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// getOwnPublicIpsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// getOwnPublicIpsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
