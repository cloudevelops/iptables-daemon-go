package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type rulesPuppet struct {
	Name   string
	Action string
	Proto  string
	Source string
}

func init() {
	err := loadConfig(".")
	if err == nil {
		file, err := os.OpenFile("/home/rested/golang/src/iptables-daemon-go/logrus.log", os.O_APPEND|os.O_WRONLY, 0666)
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
	k, err := iptables.New()
	chains, err := k.ListChains("filter")
	if err == nil {
		fmt.Println(chains)
	}
	// parse rules from location - placeholder for now
	out, err := ioutil.ReadFile(viper.GetString("file_location"))
	rules := parseJson(out)
	insertIntoIPTables(rules, k)
	fmt.Println(err)
}

func parseJson(rawJson []byte) []rulesPuppet {
	var r interface{}
	// unmarshal raw data
	if err := json.Unmarshal(rawJson, &r); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("couldn't unmarshal puppet rules")
	}
	index := 0
	// assert type - string(name of rule) and rules
	m := r.(map[string]interface{})
	// create an array of structs to save rules in
	var rules []rulesPuppet = make([]rulesPuppet, len(m))
	for i, k := range m {
		if err := mapstructure.Decode(k, &rules[index]); err == nil {
			rules[index].Name = i
			index++
		} else {
			log.Error("bad decode", err)
		}
	}
	log.Info("successfully unmarshalled ", len(rules), " rules")
	return rules
}

func insertIntoIPTables(ruleList []rulesPuppet, table *iptables.IPTables) {
	for i := range ruleList {
		if err := table.AppendUnique("filter", "INPUT", "-j", strings.ToUpper(ruleList[i].Action), "-s", ruleList[i].Source, "-p", ruleList[i].Proto); err != nil {
			log.Error("Unable to insert rule ", ruleList[i].Name, " into iptables")
		} else {
			log.WithFields(log.Fields{
				"name":   ruleList[i].Name,
				"action": ruleList[i].Action,
				"source": ruleList[i].Source,
				"proto":  ruleList[i].Proto,
			}).Info("Succesfully inserted rule!")
		}
	}
}

func loadConfig(location string) error {
	viper.SetConfigName("config")
	viper.AddConfigPath(location)
	viper.AddConfigPath(".")
	return viper.ReadInConfig()
}
