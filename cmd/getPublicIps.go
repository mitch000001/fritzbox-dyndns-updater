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
	"os"

	"github.com/mitch000001/fritzbox-dyndns-updater/pkg/fritzbox"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	fritzboxURL       string
	fritzboxUsername  string
	fritzboxPassword  string
	fritzboxVerifyTLS bool
)

// getPublicIpsCmd represents the getPublicIps command
var getPublicIpsCmd = &cobra.Command{
	Use:   "getPublicIps",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		client := fritzbox.NewUPNPClient(fritzboxURL, fritzboxUsername, fritzboxPassword, fritzboxVerifyTLS)
		externalIPv6, err := client.GetExternalIPv6Address()
		if err != nil {
			logrus.Errorf("Could not get external IPv6 address: %v", err)
			os.Exit(1)
		}
		logrus.Infof("Got external IPv6 address: %v", externalIPv6)
		externalIPv6Prefix, err := client.GetExternalIPv6Prefix()
		if err != nil {
			logrus.Errorf("Could not get external IPv6 prefix: %v", err)
			os.Exit(1)
		}
		logrus.Infof("Got external IPv6 prefix: %v", externalIPv6Prefix)
	},
}

func init() {
	rootCmd.AddCommand(getPublicIpsCmd)
	getPublicIpsCmd.Flags().StringVar(&fritzboxURL, "fritzbox.url", "http://fritz.box:49000", "specify the fritzbox endpoint")
	getPublicIpsCmd.Flags().StringVar(&fritzboxUsername, "fritzbox.username", "", "specify the fritzbox user")
	getPublicIpsCmd.Flags().StringVar(&fritzboxPassword, "fritzbox.password", "", "specify the fritzbox password")
	getPublicIpsCmd.Flags().BoolVar(&fritzboxVerifyTLS, "fritzbox.verify-tls", false, "specify if the TLS certificate needs to be verified")
}
