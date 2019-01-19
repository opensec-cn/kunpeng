// Package util 通用函数
package util

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/rand"
	"regexp"
	"time"
)

// Struct2Map 结构转map
func Struct2Map(obj interface{}) map[string]interface{} {
	jsonBytes, _ := json.Marshal(obj)
	var result map[string]interface{}
	json.Unmarshal(jsonBytes, &result)
	return result
}

// GetMd5 计算字符md5值
func GetMd5(body []byte) string {
	md5Ctx := md5.New()
	md5Ctx.Write(body)
	cipherStr := md5Ctx.Sum(nil)
	return hex.EncodeToString(cipherStr)
}

// GetRandomString 获取随机字符串
func GetRandomString(l int) string {
	return string(GetRandomBytes(l))
}

// GetRandomBytes 获取包含随机字母的 byte 数组
func GetRandomBytes(l int) []byte {
	str := "0123456789abcdefghijklmnopqrstuvwxyz"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return result
}

// InArray 判断字符串是否存在指定列表中，可开启正则判断模式
func InArray(list []string, value string, regex bool) bool {
	for _, v := range list {
		if regex {
			if ok, err := regexp.MatchString(v, value); ok {
				return true
			} else if err != nil {
				log.Println(err.Error())
			}
		} else {
			if value == v {
				return true
			}
		}
	}
	return false
}
