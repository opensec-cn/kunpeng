package util

import (
	"log"
	"os"

	"github.com/opensec-cn/kunpeng/config"
)

type logger struct {
	info    *log.Logger
	warning *log.Logger
	err     *log.Logger
}

// Logger 日志打印
var Logger logger

func init() {
	Logger.info = log.New(os.Stdout, "[info] ", log.Ltime|log.Lshortfile)
	Logger.warning = log.New(os.Stdout, "[warning] ", log.Ltime|log.Lshortfile)
	Logger.err = log.New(os.Stderr, "[error] ", log.Ltime|log.Lshortfile)
}

func (l *logger) Println(logs ...interface{}) {
	l.info.Println(logs)
}

func (l *logger) Info(logs ...interface{}) {
	if config.Debug == true {
		l.info.Println(logs)
	}
}
func (l *logger) Warning(logs ...interface{}) {
	if config.Debug == true {
		l.warning.Println(logs)
	}
}
func (l *logger) Error(logs ...interface{}) {
	if config.Debug == true {
		l.err.Println(logs)
	}
}
