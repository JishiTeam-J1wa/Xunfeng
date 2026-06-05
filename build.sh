#!/bin/bash

# XunFeng Cross-Platform Build Script
# J4Team - 寻风构建脚本

set -e

VERSION="3.0.0"
OUTPUT_DIR="build"
APP_NAME="xunfeng"

# 编译参数 (优化体积和隐匿性)
LDFLAGS="-s -w -X main.Version=${VERSION}"
GCFLAGS=""
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

    # CGO 需要特殊处理 (sqlite3)
    if [ "$GOOS" = "darwin" ] && [ "$(uname)" = "Darwin" ]; then
        CGO_ENABLED=1 GOOS=$GOOS GOARCH=$GOARCH go build \
            -ldflags "${LDFLAGS}" \
            -o "${OUTPUT_DIR}/${OUTPUT_NAME}" \
            .
    elif [ "$GOOS" = "linux" ]; then
        # Linux 需要交叉编译 CGO
        if command -v x86_64-linux-gnu-gcc &> /dev/null && [ "$GOARCH" = "amd64" ]; then
            CC=x86_64-linux-gnu-gcc CGO_ENABLED=1 GOOS=$GOOS GOARCH=$GOARCH go build \
                -ldflags "${LDFLAGS}" \
                -o "${OUTPUT_DIR}/${OUTPUT_NAME}" \
                . 2>/dev/null || echo "  [!] ${GOOS}/${GOARCH} skipped (no cross-compiler)"
        else
            echo "  [!] ${GOOS}/${GOARCH} skipped (no cross-compiler)"
        fi
    elif [ "$GOOS" = "windows" ]; then
        if command -v x86_64-w64-mingw32-gcc &> /dev/null && [ "$GOARCH" = "amd64" ]; then
            CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 GOOS=$GOOS GOARCH=$GOARCH go build \
                -ldflags "${LDFLAGS}" \
                -o "${OUTPUT_DIR}/${OUTPUT_NAME}" \
                . 2>/dev/null || echo "  [!] ${GOOS}/${GOARCH} skipped (no cross-compiler)"
        else
            echo "  [!] ${GOOS}/${GOARCH} skipped (no cross-compiler)"
        fi
    else
        CGO_ENABLED=1 GOOS=$GOOS GOARCH=$GOARCH go build \
            -ldflags "${LDFLAGS}" \
            -o "${OUTPUT_DIR}/${OUTPUT_NAME}" \
            . 2>/dev/null || echo "  [!] ${GOOS}/${GOARCH} skipped"
    fi
done

echo ""
echo "[+] Build complete!"
echo ""
ls -lh ${OUTPUT_DIR}/
