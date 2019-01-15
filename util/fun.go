package util

import (
	"log"
	"math/rand"
	"regexp"
	"time"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
)


func Struct2Map(obj interface{}) map[string]interface{} {
	jsonBytes, _ := json.Marshal(obj)
	var result map[string]interface{}
	json.Unmarshal(jsonBytes, &result)
	return result
}

func GetMd5(body []byte) string {
	md5Ctx := md5.New()
	md5Ctx.Write(body)
	cipherStr := md5Ctx.Sum(nil)
	return hex.EncodeToString(cipherStr)
}

func GetRandomString(l int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyz"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

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