package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/fsnotify/fsnotify"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type rulesPuppet struct {
	Name        string
	Action      string
	Proto       string
	Source      string
	Chain       string
	Port        string
	Destination string
	Table       string
	Jump        string
	Tosource    string
	Todest      string
	Position    int
	Ignore      int
	State       string
	// gotta add chain parameter, port
}

type ByArea []rulesPuppet

func (c ByArea) Len() int           { return len(c) }
func (c ByArea) Swap(i, j int)      { c[i], c[j] = c[j], c[i] }
func (c ByArea) Less(i, j int) bool { return c[i].Position > c[j].Position }

func init() {
	err := loadConfig("/etc/iptables-daemon-go/iptables-daemon-conf.json")
	if err == nil {
		if _, err := os.Stat("/var/log/iptables-daemon-go"); os.IsNotExist(err) {
			os.Mkdir("/var/log/iptables-daemon-go", os.FileMode(0755))
		}
		file, err := os.OpenFile("/var/log/iptables-daemon-go/default.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if err == nil {
			log.SetOutput(file)
		} else {
			log.Info("Failed to log to file, using default stderr")
		}
	} else {
		fmt.Println("can't load config, exiting")
		os.Exit(1)
	}
}

func main() {
	k, _ := iptables.New()
	watcher, _ := fsnotify.NewWatcher()
	watcher.Add(viper.GetString("file_location"))
	// initial call - applies then waits
	out, err := ioutil.ReadFile(viper.GetString("file_location"))
	if err == nil {
		rules := parseJson(out)
		insertIntoIPTables(rules, k)
	} else {
		log.Error("COuldnt parse the file", err)
	}
	// thanks fsnotify for this bit of code!! watches thefile and reapplies if something changes
	for {
		select {
		case event := <-watcher.Events:
			log.Info("event:", event)
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Info("modified file:", event.Name)
			}
			readModify(k)
		case err := <-watcher.Errors:
			log.Error("error:", err)
		}
	}
}
func readModify(table *iptables.IPTables) {
	out, err := ioutil.ReadFile(viper.GetString("file_location"))
	if err == nil {
		rules := parseJson(out)
		insertIntoIPTables(rules, table)
		deleteFromIPTables(rules, table)
	} else {
		log.Error("COuldnt parse the file", err)
	}
}

func readjustPositions(table *iptables.IPTables, rules []rulesPuppet) {
	tableChainMap := make(map[string][]string)
	for i := range rules {
		_, ok := tableChainMap[rules[i].Table]
		if !ok {
			chains, err := table.ListChains(rules[i].Table)
			if err == nil {
				tableChainMap[rules[i].Table] = chains
			}
		}
	}
	trimCount := 0
	currentChain := ""
	for i, f := range tableChainMap {
		for k := range f {
			list, _ := table.List(i, f[k])
			if len(list) > len(rules) {
				currentChain = f[k]
				trimCount = len(list) - len(rules) - 1
			}
			for i := range rules {
				if rules[i].Chain == f[k] && rules[i].Position > len(rules) {
					rules[i].Position = rules[i].Position + len(list) - 1
				}
			}
		}
	}
	for i := 1; i <= trimCount; i++ {
		fmt.Println(len(rules) + i)
		out, err := exec.Command("iptables", "-D", currentChain, strconv.Itoa(len(rules)+i)).Output()
		if err == nil {
			fmt.Println("removed excess rules", string(out))
		}
	}
}

func parseJson(rawJson []byte) []rulesPuppet {
	var r interface{}
	// unmarshal raw data

	// for i := range strings.Split(string(rawJson), "/n") {
	// fmt.Println(i)
	// }
	if err := json.Unmarshal(rawJson, &r); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("couldn't unmarshal puppet rules")
	}
	index := 0
	index2 := 1
	// assert type - string(name of rule) and rules
	m := r.(map[string]interface{})

	// create an array of structs to save rules in
	var rules []rulesPuppet = make([]rulesPuppet, len(m))
	for i, k := range m {
		if err := mapstructure.Decode(k, &rules[index]); err == nil {
			rules[index].Name = i
			pos, _ := strconv.Atoi((strings.Split(i, "-")[3]))
			rules[index].Position = pos + 1
			// fmt.Println(rules[index].Position, rules[index].Name)
			index2++
			index++
		} else {
			log.Error("bad decode on line ", i, err)
		}
	}
	log.Info("successfully unmarshalled ", len(rules), " rules")
	return rules
}
func insertIntoIPTables(ruleList []rulesPuppet, table *iptables.IPTables) {
	sort.Sort(sort.Reverse(ByArea(ruleList)))
	// fmt.Println(ruleList[i].Name, ruleList[i].Position)
	// fmt.Println(ruleList)
	// fmt.Println(len(ruleList))
	nat := false
	sourceDest := ""
	sourceDestAddr := ""
	for i := range ruleList {
		// fmt.Println(ruleList[i].Name, ruleList[i].Position)

		if ruleList[i].Table == "" {
			ruleList[i].Table = "filter"
		}
		if ruleList[i].Chain == "" {
			ruleList[i].Chain = "INPUT"
		}
		if ruleList[i].Destination == "" {
			// fmt.Println(len(ruleList[i].Destination))
			ruleList[i].Destination = "0.0.0.0/0"
		}
		if ruleList[i].Source == "" {
			ruleList[i].Source = "0.0.0.0/0"
		}
		// fmt.Println(ruleList[i].Source[0].IP, ruleList[i].Destination)
		if ruleList[i].Action == "" {
			ruleList[i].Action = ruleList[i].Jump
		}
		// fmt.Println(ruleList[i], i)
		if errCreate := table.NewChain(ruleList[i].Table, ruleList[i].Chain); errCreate == nil {
			log.Info("Created chain ", ruleList[i].Chain, " in table ", ruleList[i].Table)
		}
		if ruleList[i].Action == "DNAT" || ruleList[i].Action == "SNAT" {
			nat = true
			if ruleList[i].Tosource == "" {
				sourceDest = "--to-destination"
				sourceDestAddr = ruleList[i].Todest
			} else if ruleList[i].Todest == "" {
				sourceDest = "--to-source"
				sourceDestAddr = ruleList[i].Tosource
			}
		}
	}
	readjustPositions(table, ruleList)
	// fmt.Println(ruleList[i].Name, ruleList[i].Position)
	for i := range ruleList {
		// fmt.Println(ruleList[i].Name, ruleList[i].Position)
		if ruleList[i].State != "" {
			if exists, err := table.Exists(ruleList[i].Table, strings.ToUpper(ruleList[i].Chain), "-m", "state", "--state", strings.ToUpper(ruleList[i].State), "-j", ruleList[i].Action); !exists && err == nil {
				if err0 := table.Insert(ruleList[i].Table, strings.ToUpper(ruleList[i].Chain), ruleList[i].Position, "-m", "state", "--state", strings.ToUpper(ruleList[i].State), "-j", ruleList[i].Action); err0 != nil {
					log.Error("Unable to insert rule ", ruleList[i].Name, " into iptables-", err0.Error())
				} else {
					logRule(ruleList[i], "Succesfully inserted")
				}
			} else {
				logRule(ruleList[i], "Was not inserted - already exists or failed to insert")
				if err != nil {
					log.Error(err.Error())
				}
			}
		}
		if ruleList[i].Port == "" {
			// original iptables.go has dumb logic on their appendUnique func - didn't rewrite the source package, i'd rather add a few lines than break this for everyone else who'd have to edit this
			if !nat {
				if exists, err := table.Exists(ruleList[i].Table, strings.ToUpper(ruleList[i].Chain), "-j", strings.ToUpper(ruleList[i].Action), "-s", ruleList[i].Source, "-d", ruleList[i].Destination, "-p", ruleList[i].Proto, "-m", "comment", "--comment", ruleList[i].Name); !exists && err == nil {
					if err0 := table.Insert(ruleList[i].Table, strings.ToUpper(ruleList[i].Chain), ruleList[i].Position, "-j", strings.ToUpper(ruleList[i].Action), "-s", ruleList[i].Source, "-d", ruleList[i].Destination, "-p", ruleList[i].Proto, "-m", "comment", "--comment", ruleList[i].Name); err0 != nil {
						log.Error("Unable to insert rule ", ruleList[i].Name, " into iptables-", err0.Error())
					} else {
						logRule(ruleList[i], "Succesfully inserted")
					}
				} else {
					logRule(ruleList[i], "Was not inserted - already exists or failed to insert")
					if err != nil {
						log.Error(err.Error())
					}
				}
			} else {
				if exists, err := table.Exists(ruleList[i].Table, strings.ToUpper(ruleList[i].Chain), "-j", strings.ToUpper(ruleList[i].Action), "-s", ruleList[i].Source, "-d", ruleList[i].Destination, "-p", ruleList[i].Proto, "-m", "comment", "--comment", ruleList[i].Name, sourceDest, sourceDestAddr); !exists {
					if err0 := table.Insert(ruleList[i].Table, strings.ToUpper(ruleList[i].Chain), ruleList[i].Position, "-j", strings.ToUpper(ruleList[i].Action), "-s", ruleList[i].Source, "-d", ruleList[i].Destination, "-p", ruleList[i].Proto, "-m", "comment", "--comment", ruleList[i].Name, sourceDest, sourceDestAddr); err0 != nil {
						log.Error("Unable to insert rule ", ruleList[i].Name, " into iptables-", err0.Error())
					} else {
						logRule(ruleList[i], "Succesfully inserted")
					}
				} else {
					logRule(ruleList[i], "Was not inserted - already exists or failed to insert")
					if err != nil {
						log.Error(err.Error())
					}
				}
			}
		} else {
			if !nat {
				if exists, err := table.Exists(ruleList[i].Table, strings.ToUpper(ruleList[i].Chain), "-j", strings.ToUpper(ruleList[i].Action), "-s", ruleList[i].Source, "-d", ruleList[i].Destination, "-p", ruleList[i].Proto, "--match", "multiport", "--dport", ruleList[i].Port, "-m", "comment", "--comment", ruleList[i].Name); !exists && err == nil {
					// fmt.Printf("%+v\n", ruleList[11])
					if err0 := table.Insert(ruleList[i].Table, strings.ToUpper(ruleList[i].Chain), ruleList[i].Position, "-j", strings.ToUpper(ruleList[i].Action), "-s", ruleList[i].Source, "-d", ruleList[i].Destination, "-p", ruleList[i].Proto, "--match", "multiport", "--dport", ruleList[i].Port, "-m", "comment", "--comment", ruleList[i].Name); err0 != nil {
						log.Error("Unable to insert rule ", ruleList[i].Name, " into iptables-", err.Error())
					} else {
						logRule(ruleList[i], "Succesfully inserted")
					}
				} else {
					logRule(ruleList[i], "Was not inserted - already exists or failed to insert")
					if err != nil {
						log.Error(err.Error())
					}
				}
			} else {
				if exists, err := table.Exists(ruleList[i].Table, strings.ToUpper(ruleList[i].Chain), "-j", strings.ToUpper(ruleList[i].Action), "-s", ruleList[i].Source, "-d", ruleList[i].Destination, "-p", ruleList[i].Proto, "--match", "multiport", "--dport", ruleList[i].Port, "-m", "comment", "--comment", ruleList[i].Name, sourceDest, sourceDestAddr); !exists && err == nil {
					if err0 := table.Insert(ruleList[i].Table, strings.ToUpper(ruleList[i].Chain), ruleList[i].Position, "-j", strings.ToUpper(ruleList[i].Action), "-s", ruleList[i].Source, "-d", ruleList[i].Destination, "-p", ruleList[i].Proto, "--match", "multiport", "--dport", ruleList[i].Port, "-m", "comment", "--comment", ruleList[i].Name, sourceDest, sourceDestAddr); err0 != nil {
						log.Error("Unable to insert rule ", ruleList[i].Name, " into iptables-", err.Error())
					} else {
						logRule(ruleList[i], "Succesfully inserted at position")
					}
				} else {
					logRule(ruleList[i], "Was not inserted - already exists or failed to insert")
					if err != nil {
						log.Error(err.Error())
					}
				}
			}
		}
	}
	log.Info("Rules have been applied")
	fmt.Println("Done.")

}

func deleteFromIPTables(rules []rulesPuppet, table *iptables.IPTables) {
	tableChainMap := make(map[string][]string)

	for i := range rules {
		_, ok := tableChainMap[rules[i].Table]
		if !ok {
			chains, err := table.ListChains(rules[i].Table)
			if err == nil {
				tableChainMap[rules[i].Table] = chains
			}
		}
	}
	for i, f := range tableChainMap {
		for k := range f {
			list, _ := table.List(i, f[k])
			// fmt.Println(list)
			for d := range list {
				found := false
				sublist := strings.Fields(list[d])
				if len(sublist) > 3 {
					ruleSubstituted := strings.Replace(strings.Join(sublist, " "), "-A", "-C", 1)
					_, err := exec.Command("iptables", ruleSubstituted).Output()
					if err.Error() == "exit status 1" {
						for r := range rules {
							for n := range sublist {
								if rules[r].Name == sublist[n] {
									found = true
								}
							}
							if rules[r].Ignore == 1 {
								found = true
							}
						}
					}
					if !found {
						fmt.Println(ruleSubstituted + " not found in json")
						ruleSubstituted = strings.Replace(strings.Join(sublist, " "), "-A", "-D", 1)

						cmd := "iptables " + ruleSubstituted
						if out0, err := exec.Command("bash", "-c", cmd).CombinedOutput(); err == nil {
							log.Info("SUccesfully deleted rule", ruleSubstituted, "from table", f[k])
						} else {
							log.Error("Couldn't delete rule", ruleSubstituted, "in table", f[k], "iptables output:", err, out0)
						}
					}
				}
			}
		}
	}

}

// fmt.Printf("%+v\n", rules)

func loadConfig(location string) error {
	viper.SetConfigName("config")
	viper.AddConfigPath(location)
	viper.AddConfigPath(".")
	return viper.ReadInConfig()
}

func logRule(rule rulesPuppet, info string) {
	log.WithFields(log.Fields{
		"name":   rule.Name,
		"table":  rule.Table,
		"action": rule.Action,
		"source": rule.Source,
		"proto":  rule.Proto,
		"chain":  rule.Chain,
		// "port":   rule.Port,
		// "error": err,
	}).Info(info)
}
