//go:build !windows

package main

import "os"

// isPrivileged 判断当前进程是否以 root 权限运行
func isPrivileged() bool {
	return os.Geteuid() == 0
}
