#!/bin/bash

# XunFeng Cross-Platform Build Script
# J4Team - 寻风构建脚本
#
# 默认使用 CGO_ENABLED=0，通过 modernc.org/sqlite 纯 Go 实现支持浏览器数据库读取，
# 从而在无交叉编译器环境下也能一次性构建 Windows/Linux/macOS 全平台二进制。
# 如果本地存在对应平台编译器且希望使用 mattn/go-sqlite3，可设置 USE_CGO=1 启用。

set -e

VERSION="4.0.0"
OUTPUT_DIR="build"
APP_NAME="xunfeng"
USE_CGO="${USE_CGO:-0}"

# 编译参数 (优化体积)
LDFLAGS="-s -w -X main.Version=${VERSION}"
TAGS="netgo"

echo "=========================================="
echo "  XunFeng Builder v${VERSION}"
echo "  J4Team - 寻风构建工具"
echo "=========================================="
echo ""

# 清理旧的构建
rm -rf ${OUTPUT_DIR}
mkdir -p ${OUTPUT_DIR}

# 平台列表
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
    if [ "$GOOS" = "windows" ]; then
        OUTPUT_NAME="${OUTPUT_NAME}.exe"
    fi

    echo "[*] Building ${GOOS}/${GOARCH}..."

    CGO_FLAG=0
    CC_FLAG=""

    # 仅在显式启用 CGO 且存在对应编译器时尝试使用 CGO
    if [ "$USE_CGO" = "1" ]; then
        if [ "$GOOS" = "darwin" ] && [ "$(uname)" = "Darwin" ]; then
            CGO_FLAG=1
        elif [ "$GOOS" = "linux" ] && [ "$GOARCH" = "amd64" ] && command -v x86_64-linux-gnu-gcc &> /dev/null; then
            CGO_FLAG=1
            CC_FLAG="CC=x86_64-linux-gnu-gcc"
        elif [ "$GOOS" = "windows" ] && [ "$GOARCH" = "amd64" ] && command -v x86_64-w64-mingw32-gcc &> /dev/null; then
            CGO_FLAG=1
            CC_FLAG="CC=x86_64-w64-mingw32-gcc"
        fi
    fi

    env ${CC_FLAG} CGO_ENABLED=${CGO_FLAG} GOOS=${GOOS} GOARCH=${GOARCH} \
        go build -tags "${TAGS}" -ldflags "${LDFLAGS}" \
        -o "${OUTPUT_DIR}/${OUTPUT_NAME}" \
        . || echo "  [!] ${GOOS}/${GOARCH} build failed"
done

echo ""
echo "[+] Build complete!"
echo ""
ls -lh ${OUTPUT_DIR}/
