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
	"os"
	"strings"

	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/dns"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// getOwnPublicIpsCmd represents the getOwnPublicIps command
var getOwnPublicIpsCmd = &cobra.Command{
	Use:   "getOwnPublicIps",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		resolver := dns.NewWebResolver(dns.WebResolverConfig{})
		ips, err := resolver.GetPublicIPs(cmd.Context())
		if err != nil {
			logrus.Errorf("error getting public IPs: %v", err)
			os.Exit(1)
			return
		}
		logrus.Infof("Got external IP addresses: %d", len(ips))
		var ipStrings []string
		for _, ip := range ips {
			if ip.IsPrefix {
				ipStrings = append(ipStrings, ip.Prefix.String())
				continue
			}
			ipStrings = append(ipStrings, ip.Prefix.Addr().String())
		}
		fmt.Printf("%s", strings.Join(ipStrings, "\n"))
	},
}

func init() {
	rootCmd.AddCommand(getOwnPublicIpsCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// getOwnPublicIpsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// getOwnPublicIpsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
