package util

import (
	"log"
	"os"

	"github.com/opensec-cn/kunpeng/config"
)

var logger = log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)

// Log 打印日志
func Log(level string, log string) {
	if config.Debug == true {
		logger.SetPrefix("[" + level + "] ")
		logger.Println(log)
	}
}
