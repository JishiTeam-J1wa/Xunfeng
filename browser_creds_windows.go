//go:build windows

package main

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dataBlob 对应 crypt32.dll 的 DATA_BLOB 结构
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// dpapiDecrypt 调用 CryptUnprotectData 解密 DPAPI 保护的数据
// （以当前用户身份运行时可解密当前用户加密的 Local State 主密钥）
func dpapiDecrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty dpapi blob")
	}
	proc := windows.NewLazySystemDLL("crypt32.dll").NewProc("CryptUnprotectData")

	in := dataBlob{cbData: uint32(len(data)), pbData: &data[0]}
	var out dataBlob
	r, _, err := proc.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // ppszDataDescr
		0, // pOptionalEntropy
		0, // pvReserved
		0, // pPromptStruct
		0, // dwFlags
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.pbData))))

	result := make([]byte, out.cbData)
	copy(result, unsafe.Slice(out.pbData, out.cbData))
	return result, nil
}

// safeStoragePassword 仅用于 macOS，Windows 上不使用
func safeStoragePassword(service string) (string, error) {
	return "", errors.New("safe storage not supported on windows")
}
