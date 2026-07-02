//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

// isPrivileged 判断当前进程是否以管理员权限运行
func isPrivileged() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}
