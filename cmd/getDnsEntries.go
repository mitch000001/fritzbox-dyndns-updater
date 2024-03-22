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
	"context"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// getDnsEntriesCmd represents the getDnsEntries command
var getDnsEntriesCmd = &cobra.Command{
	Use:   "getDnsEntries",
	Short: "Get IPs for the provided dns entries ",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		resolver := net.Resolver{}
		var results = map[string][]net.IPAddr{}
		for _, entry := range dnsNames {
			res, err := resolver.LookupIPAddr(context.Background(), entry)
			if err != nil {
				logrus.Errorf("Error looking up dns name %q: %v", entry, err)
			}
			results[entry] = res
		}
		for name, ips := range results {
			fmt.Printf("%s: %v\n", name, ips)
		}
	},
}

var dnsNames []string

func init() {
	rootCmd.AddCommand(getDnsEntriesCmd)
	getDnsEntriesCmd.Flags().StringArrayVar(&dnsNames, "dns-entries", []string{}, "specifies the dns entries to look up")
}
