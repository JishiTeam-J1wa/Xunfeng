//go:build windows

package main

// getWindowsPrivescExploits 根据 Windows 构建号返回匹配漏洞
func getWindowsPrivescExploits() []privescExploit {
	v := getWindowsVersion()
	var out []privescExploit

	for _, exp := range windowsPrivescDB {
		if exp.CVE != "" && windowsBuildVulnerable(v, exp) {
			out = append(out, exp)
		}
	}

	// 通用配置问题建议
	for _, exp := range windowsPrivescDB {
		if exp.CVE == "" {
			out = append(out, exp)
		}
	}

	return out
}

// windowsBuildVulnerable 粗略判断该构建号是否在漏洞影响范围内
func windowsBuildVulnerable(v windowsVersion, exp privescExploit) bool {
	switch exp.CVE {
	case "CVE-2019-1132":
		// Win7/8.1/Win10 1803 及更早
		return v.Build > 0 && v.Build <= 17134
	case "CVE-2020-0796":
		// Win10 1903/1909
		return v.Build == 18362 || v.Build == 18363
	case "CVE-2021-34527":
		// PrintNightmare 影响范围极广
		return v.Build >= 7600
	case "CVE-2021-41379":
		return v.Build >= 17763
	case "CVE-2022-26809":
		return v.Build >= 7600
	case "CVE-2022-24521":
		return v.Build >= 17763
	case "CVE-2023-29360":
		return v.Build >= 17763
	case "CVE-2024-30085":
		return v.Build >= 19041
	case "CVE-2024-38063":
		return v.Build >= 19041
	}
	return false
}
