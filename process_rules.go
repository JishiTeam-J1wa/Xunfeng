package main

import (
	_ "embed"
	"encoding/json"
	"regexp"
)

//go:embed assets/process_rules.json
var processRulesJSON []byte

// ProcessRule 描述一个进程识别规则（支持从 JSON 动态加载）
type ProcessRule struct {
	Name      string   `json:"name"`
	Category  string   `json:"category"`
	Pattern   string   `json:"pattern"`
	Processes []string `json:"processes"`
	re        *regexp.Regexp
}

// externalProcessRules 从嵌入的 JSON 加载的进程规则（如 EDR/AV/安全产品）
var externalProcessRules []*ProcessRule

func init() {
	loadProcessRules()
}

func loadProcessRules() {
	var rules []ProcessRule
	if err := json.Unmarshal(processRulesJSON, &rules); err != nil {
		return
	}
	for i := range rules {
		if rules[i].Pattern == "" || len(rules[i].Processes) == 0 {
			continue
		}
		re, err := regexp.Compile(rules[i].Pattern)
		if err != nil {
			continue
		}
		rules[i].re = re
		externalProcessRules = append(externalProcessRules, &rules[i])
	}
}
