package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/Knetic/govaluate"
	"gopkg.in/yaml.v2"
	"log"
	"os"
)

type Rules struct {
	Name,
	Applications string
	Definitions []*Rule
}

type Rule struct {
	Name,
	Description,
	Condition,
	Level,
	RuleType,
	Tags,
	ExtType string
}

func main() {
	//count := 0
	rulesMap := make(map[string]*Rules)

	file, err := os.Open("./rules4.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		line := scanner.Bytes()
		m := make(map[string]string)
		err := json.Unmarshal(line, &m)
		if err != nil {
			log.Fatal(err)
		}
		_, err = govaluate.NewEvaluableExpression(m["condition"])
		if err != nil {
			fmt.Println(string(line))
			fmt.Println(m["condition"])
			log.Fatal(err)
		}
		if groupName, ok := m["groupName"]; ok {
			if rules, ok := rulesMap[groupName]; ok {
				rules.Definitions = append(rules.Definitions, &Rule{
					Name:        m["name"],
					Description: m["description"],
					Condition:   m["condition"],
					Level:       m["level"],
					RuleType:    "EVALUATE",
					Tags:        m["tags"],
					ExtType:     "SIEM",
				})
			} else {
				rules = &Rules{
					Name:         groupName,
					Applications: "",
					Definitions: []*Rule{
						{
							Name:        m["name"],
							Description: m["description"],
							Condition:   m["condition"],
							Level:       m["level"],
							RuleType:    "EVALUATE",
							Tags:        m["tags"],
							ExtType:     "SIEM",
						},
					},
				}
				rulesMap[groupName] = rules
			}
		}
	}
	for groupName, rules := range rulesMap {

		bts, err := yaml.Marshal(rules)
		if err != nil {
			log.Fatal(err)
		}

		f, err := os.OpenFile(fmt.Sprintf("logiqrules/%s.yaml",groupName), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		_, err = f.Write(bts)
		if err != nil {
			log.Fatal(err)
		}
		err = f.Sync()
		if err != nil {
			log.Fatal(err)
		}
		err = f.Close()
		if err != nil {
			log.Fatal(err)
		}
	}
}
