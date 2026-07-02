package main

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

var (
	silent bool

	// 标准输出缓冲与锁
	stdoutWriter = bufio.NewWriter(os.Stdout)
	stdoutMu     sync.Mutex
	flushOnce    sync.Once

	// 实时日志
	liveLogChan   = make(chan string, 8192)
	liveLogDone   = make(chan struct{})
	liveLogFile   *os.File
	liveLogWriter *bufio.Writer
	liveLogOnce   sync.Once

	// 进度状态
	progressing atomic.Bool

	// 颜色
	cyan    = color.New(color.FgCyan).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	magenta = color.New(color.FgMagenta).SprintFunc()
	white   = color.New(color.FgWhite, color.Bold).SprintFunc()
)

// startConsoleWriter 启动后台定时刷新，避免每条消息都 flush 导致终端卡顿
func startConsoleWriter() {
	flushOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for range ticker.C {
				stdoutMu.Lock()
				stdoutWriter.Flush()
				stdoutMu.Unlock()
			}
		}()
	})
}

// consolePrint 直接写入终端缓冲区并解锁；flush 由后台 goroutine 负责
func consolePrint(msg string) {
	if silent {
		return
	}
	stdoutMu.Lock()
	// 如果当前有进度条在显示，先清空该行再输出发现，避免交错
	if progressing.Load() {
		fmt.Fprint(stdoutWriter, "\r\033[K")
	}
	fmt.Fprintln(stdoutWriter, msg)
	stdoutMu.Unlock()
}

// consolePrintf 格式化后输出
func consolePrintf(format string, args ...interface{}) {
	consolePrint(fmt.Sprintf(format, args...))
}

// consoleFlush 立即刷新终端（用于 banner/section 等需要立即显示的场景）
func consoleFlush() {
	stdoutMu.Lock()
	stdoutWriter.Flush()
	stdoutMu.Unlock()
}

// setupLiveLog 初始化实时日志文件（追加模式），并启动后台写入 goroutine
func setupLiveLog(path string) error {
	var initErr error
	liveLogOnce.Do(func() {
		livePath := path + ".live.txt"
		f, err := os.OpenFile(livePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_TRUNC, 0644)
		if err != nil {
			initErr = err
			return
		}
		liveLogFile = f
		liveLogWriter = bufio.NewWriterSize(f, 256*1024)

		// 写入表头
		liveLogWriter.WriteString(fmt.Sprintf("# XunFeng Live Log - %s\n", time.Now().Format("2006-01-02 15:04:05")))
		liveLogWriter.WriteString("# 实时记录扫描过程中的发现，崩溃/中断时可从此文件恢复结果\n")
		liveLogWriter.Flush()

		// 后台写入 + 定时刷盘
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			defer close(liveLogDone)
			defer func() {
				if liveLogWriter != nil {
					liveLogWriter.Flush()
				}
				if liveLogFile != nil {
					liveLogFile.Close()
				}
			}()
			for {
				select {
				case msg, ok := <-liveLogChan:
					if !ok {
						return
					}
					liveLogWriter.WriteString(msg)
					liveLogWriter.WriteByte('\n')
				case <-ticker.C:
					liveLogWriter.Flush()
				}
			}
		}()
	})
	return initErr
}

// writeLiveLog 追加一行到实时日志队列
func writeLiveLog(msg string) {
	select {
	case liveLogChan <- msg:
	default:
		// 队列满时阻塞等待，确保关键发现不丢失
		liveLogChan <- msg
	}
}

// flushLiveLog 关闭实时日志通道并等待后台 goroutine 结束
func flushLiveLog() {
	close(liveLogChan)
	<-liveLogDone
}

// printInfo 信息输出
func printInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !silent {
		consolePrint(fmt.Sprintf("[%s] %s", cyan("*"), msg))
	}
	writeLiveLog(fmt.Sprintf("[*] %s", msg))
}

// printSuccess 发现输出
func printSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	atomic.AddUint64(&totalFindings, 1)
	if !silent {
		consolePrint(fmt.Sprintf("[%s] %s", green("+"), msg))
	}
	writeLiveLog(fmt.Sprintf("[+] %s", msg))
}

// printWarning 警告输出
func printWarning(format string, args ...interface{}) {
	if !silent {
		consolePrint(fmt.Sprintf("[%s] %s", yellow("!"), fmt.Sprintf(format, args...)))
	}
}

// printSection 分段标题
func printSection(title string) {
	if !silent {
		consolePrint(fmt.Sprintf("\n%s %s %s", yellow("━━━━━━━━━━"), white(title), yellow("━━━━━━━━━━")))
	}
	writeLiveLog(fmt.Sprintf("\n========== %s ==========", title))
}

// printFinding 按严重等级输出一条发现
func printFinding(severity Severity, category, path string, line int, match string) {
	atomic.AddUint64(&totalFindings, 1)
	if !silent {
		label := severity.String()
		colorFn := severity.Color()
		if line > 0 {
			consolePrintf("[%s] %-15s %s:%d  %s", colorFn(label), category, path, line, match)
		} else {
			consolePrintf("[%s] %-15s %s  %s", colorFn(label), category, path, match)
		}
	}
	writeLiveLog(fmt.Sprintf("[%s] %s %s %d %s", severity.String(), category, path, line, match))
}

// printBanner 打印 banner
func printBanner() {
	if silent {
		return
	}
	banner := `
   ██╗  ██╗██╗   ██╗███╗   ██╗███████╗███████╗███╗   ██╗ ██████╗
   ╚██╗██╔╝██║   ██║████╗  ██║██╔════╝██╔════╝████╗  ██║██╔════╝
    ╚███╔╝ ██║   ██║██╔██╗ ██║█████╗  █████╗  ██╔██╗ ██║██║  ███╗
    ██╔██╗ ██║   ██║██║╚██╗██║██╔══╝  ██╔══╝  ██║╚██╗██║██║   ██║
   ██╔╝ ██╗╚██████╔╝██║ ╚████║██║     ███████╗██║ ╚████║╚██████╔╝
   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝
                                            %s
`
	stdoutMu.Lock()
	fmt.Fprintf(stdoutWriter, cyan(banner), yellow("v3.0 by J4Team"))
	fmt.Fprintln(stdoutWriter)
	stdoutWriter.Flush()
	stdoutMu.Unlock()
}

// printProgress 输出进度（覆盖同一行）
func printProgress(scanned, findings uint64) {
	if silent {
		return
	}
	stdoutMu.Lock()
	fmt.Fprintf(stdoutWriter, "\r[*] Progress: %s files scanned | %s findings%s",
		cyan(fmt.Sprintf("%d", scanned)),
		magenta(fmt.Sprintf("%d", findings)),
		"          ")
	stdoutWriter.Flush()
	stdoutMu.Unlock()
}
