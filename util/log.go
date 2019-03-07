package util

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/opensec-cn/kunpeng/config"
)

type logger struct {
	info         *log.Logger
	warning      *log.Logger
	err          *log.Logger
	bufferStart  bool
	buffer       []string
	bufferLogLen int
}

//最大buffer可以放的字符串长度
const maxBufferLogLen = 4096

// Logger 日志打印
var Logger logger

func init() {
	Logger.info = log.New(os.Stdout, "[info] ", log.Ltime|log.Lshortfile)
	Logger.warning = log.New(os.Stdout, "[warning] ", log.Ltime|log.Lshortfile)
	Logger.err = log.New(os.Stderr, "[error] ", log.Ltime|log.Lshortfile)
	Logger.buffer = make([]string, 0, 0)
	Logger.bufferStart = false
	Logger.bufferLogLen = 0
}

func (l *logger) Println(logs ...interface{}) {
	l.info.Println(logs)
	l.Buffer(logs)
}

func (l *logger) Info(logs ...interface{}) {
	l.Buffer(logs)
	if config.Debug == true {
		l.info.Println(logs)
	}
}
func (l *logger) Warning(logs ...interface{}) {
	l.Buffer(logs)
	if config.Debug == true {
		l.warning.Println(logs)
	}
}
func (l *logger) Error(logs ...interface{}) {
	l.Buffer(logs)
	if config.Debug == true {
		l.err.Println(logs)
	}
}

//缓存所有的log数据到一个切片当中，用来返回给调用的第三方
func (l *logger) Buffer(logs ...interface{}) {
	if l.bufferStart {
		//为防止内存泄露,加上了最大长度限制
		if l.bufferLogLen <= maxBufferLogLen {
			bufferMessage := fmt.Sprintln(logs)
			l.buffer = append(l.buffer, bufferMessage)
			l.bufferLogLen += len(bufferMessage)
		}
	}
}

//开启缓存
func (l *logger) StartBuffer() {
	l.bufferStart = true
}

//完成两个功能
//重置归位，释放使用的内存
//返回buffer当中的内容，用 sep 连接起来
func (l *logger) BufferContent(sep string) string {
	message := strings.Join(l.buffer, sep)
	l.buffer = make([]string, 0, 0)
	l.bufferStart = false
	l.bufferLogLen = 0
	return message
}
