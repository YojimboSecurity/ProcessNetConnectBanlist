/*
Copyright © 2020 David Johnson <david@yojimbosecurity.ninja>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package src

import (
	"io/ioutil"
	"net/http"
	"fmt"
	"github.com/shirou/gopsutil/process"
	"log"
	"strings"
)

// BDLicensestring represents the licensing for Binary Defense Artillery Threat Intelligence Feed
// this licensing will be removed from the get responce to create the banlist.
const BDLicensestring = `#
#
#
# Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed
# https://www.binarydefense.com
#
# Note that this is for public use only.
# The ATIF feed may not be used for commercial resale or in products that are charging fees for such services.
# Use of these feeds for commerical (having others pay for a service) use is strictly prohibited.
#
#
#
`

// BDBanlist groups together the method for getting the banlist and the container for storing the banlist. 
// As well as checks if an ipaddress is in the banlist 
type BDBanlist struct{
	banlist []string
}

// Get method gets and sets banlist
func (b *BDBanlist) Get()  {
	resp, _ := http.Get("https://www.binarydefense.com/banlist.txt")
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body) 
	s := strings.ReplaceAll(string(body), BDLicensestring, "")
	b.banlist = strings.Split(s, "\n")
}

// Contains checks if an ipaddress is in the banlist
func (b *BDBanlist) Contains(ipaddress string) bool{
	for _, banedIP := range b.banlist {
        if banedIP == ipaddress {
            return true
        }
    }
    return false
}

// Process takes a pid and checks this processes network connections for ipaddresses in the banlist
func Process(pid int, banlist *BDBanlist) {
	// create proc
	proc, err := process.Processes()
	if err != nil {
		log.Fatal("oops")
	}
	p := proc[pid]

	// get connections
	connect, err := p.Connections()
	if err != nil {
		fmt.Println("connection error")
	}
	if len(connect) > 0 {
		// loop over connections
		for _, i := range connect{
			if i.Status == "ESTABLISHED"{
				if banlist.Contains(i.Raddr.IP){
					name, _ := p.Name()
					exe, _ := p.Exe()
					fmt.Println("[!] Established connected to banded IP address.")
					fmt.Printf("    PID: %v\n    Name: %v\n    Exe: %v\n", p.Pid, name, exe)			
					fmt.Printf("    Baned IPAddress: %v\n",i.Raddr.IP)
				}
			}
	
		}
	}
}

func Monitor() {
	// get pids
	pids, err := process.Pids()
	if err != nil {
		log.Fatal("Shit happened!")
	}
	// get BDBanlist
	banlist := BDBanlist{}
	banlist.Get()
	// loop over pids
	for pid := range pids {
		if pid == 0 {
			continue
		}
		// check process for network connection
		Process(pid, &banlist)
	}
}