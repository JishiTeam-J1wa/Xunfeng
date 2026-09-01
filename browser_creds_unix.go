//go:build !windows

package main

import (
	"errors"
	"os/exec"
	"runtime"
	"strings"
)

// dpapiDecrypt 仅用于 Windows，Unix 平台上不使用
func dpapiDecrypt(data []byte) ([]byte, error) {
	return nil, errors.New("dpapi not supported on this platform")
}

// safeStoragePassword 通过 macOS security 命令从 Keychain 读取
// Chromium 的 Safe Storage 密码（如 "Chrome Safe Storage"）
func safeStoragePassword(service string) (string, error) {
	if runtime.GOOS != "darwin" || service == "" {
		return "", errors.New("safe storage not supported on this platform")
	}
	out, err := exec.Command("security", "find-generic-password", "-w", "-s", service).Output()
	if err != nil {
		return "", err
	}
	pw := strings.TrimRight(string(out), "\r\n")
	if pw == "" {
		return "", errors.New("empty safe storage password")
	}
	return pw, nil
}
