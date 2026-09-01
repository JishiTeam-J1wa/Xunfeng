#!/bin/bash

# XunFeng Obfuscated Build Script
# 使用 garble 进行代码混淆，并生成多平台二进制、DLL/共享库和插件

set -e

VERSION="4.0.0"
OUTPUT_DIR="build_obfuscated"
APP_NAME="xunfeng"

# 检测 garble
GARBLE_CMD=$(command -v garble || true)
if [ -z "$GARBLE_CMD" ]; then
    GARBLE_CMD="$(go env GOPATH)/bin/garble"
    if [ ! -x "$GARBLE_CMD" ]; then
        echo "[!] garble not found. Install with: go install mvdan.cc/garble@v0.15.0"
        exit 1
    fi
fi

echo "Using garble: $GARBLE_CMD"
$GARBLE_CMD version

# 编译参数：剥离符号 + 混淆
LDFLAGS="-s -w -X main.Version=${VERSION}"
GARBLE_FLAGS="-literals -tiny"

# 清理输出目录
rm -rf ${OUTPUT_DIR}
mkdir -p ${OUTPUT_DIR}

echo ""
echo "=========================================="
echo "  XunFeng Obfuscated Builder v${VERSION}"
echo "=========================================="
echo ""

# 普通可执行文件（全平台）
echo "[*] Building obfuscated executables..."
PLATFORMS=(
    "darwin/amd64"
    "darwin/arm64"
    "linux/amd64"
    "linux/386"
    "linux/arm64"
    "windows/amd64"
    "windows/386"
)

for PLATFORM in "${PLATFORMS[@]}"; do
    GOOS=${PLATFORM%/*}
    GOARCH=${PLATFORM#*/}
    OUTPUT_NAME="${APP_NAME}_${GOOS}_${GOARCH}"
    [ "$GOOS" = "windows" ] && OUTPUT_NAME="${OUTPUT_NAME}.exe"

    echo "  [+] ${GOOS}/${GOARCH}..."
    env GOOS=${GOOS} GOARCH=${GOARCH} \
        ${GARBLE_CMD} ${GARBLE_FLAGS} build -ldflags "${LDFLAGS}" \
        -o "${OUTPUT_DIR}/${OUTPUT_NAME}" \
        . || echo "  [!] ${GOOS}/${GOARCH} build failed"
done

# c-shared 库（本机平台，跨平台 c-shared 需要对应编译器）
echo ""
echo "[*] Building c-shared libraries (host platform)..."

# macOS dylib
if [ "$(uname)" = "Darwin" ]; then
    echo "  [+] darwin/amd64 dylib..."
    GOARCH=$(uname -m)
    [ "$GOARCH" = "x86_64" ] && GOARCH=amd64
    go build -buildmode=c-shared -ldflags "${LDFLAGS}" \
        -o "${OUTPUT_DIR}/${APP_NAME}_darwin_${GOARCH}.dylib" \
        . || echo "  [!] darwin dylib build failed"
fi

# Linux so（需要本机是 Linux）
if [ "$(uname)" = "Linux" ]; then
    echo "  [+] linux/amd64 so..."
    go build -buildmode=c-shared -ldflags "${LDFLAGS}" \
        -o "${OUTPUT_DIR}/${APP_NAME}_linux_amd64.so" \
        . || echo "  [!] linux so build failed"
fi

# 插件（macOS/Linux 支持）
# 注意：plugin 模式需要导出固定的 Go 符号名，如果使用 garble 混淆，外部将无法通过名称查找符号
# 因此 plugin 只进行符号剥离，不做代码混淆
echo ""
echo "[*] Building Go plugins (host platform, symbols stripped only)..."
if [ "$(uname)" = "Darwin" ]; then
    echo "  [+] darwin plugin..."
    go build -tags "plugin" -buildmode=plugin -ldflags "${LDFLAGS}" \
        -o "${OUTPUT_DIR}/${APP_NAME}_darwin_amd64.plugin" \
        . || echo "  [!] darwin plugin build failed"
elif [ "$(uname)" = "Linux" ]; then
    echo "  [+] linux plugin..."
    go build -tags "plugin" -buildmode=plugin -ldflags "${LDFLAGS}" \
        -o "${OUTPUT_DIR}/${APP_NAME}_linux_amd64.plugin" \
        . || echo "  [!] linux plugin build failed"
fi

echo ""
echo "[+] Build complete!"
echo ""
ls -lh ${OUTPUT_DIR}/
