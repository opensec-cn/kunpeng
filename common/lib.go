package common

import (
	"reflect"
	"strings"
	"fmt"
	"crypto/md5"
	"encoding/hex"
)

func Struct2Map(obj interface{}) map[string]string {
	t := reflect.TypeOf(obj)
	v := reflect.ValueOf(obj)

	var data = make(map[string]string)
	for i := 0; i < t.NumField(); i++ {
		if v.Field(i).Type().String() == "int" {
			data[strings.ToLower(t.Field(i).Name)] = fmt.Sprintf("%d", v.Field(i).Int())
		} else {
			data[strings.ToLower(t.Field(i).Name)] = v.Field(i).String()
		}
	}
	return data
}

func GetMd5(body []byte) string {
	md5Ctx := md5.New()
	md5Ctx.Write(body)
	cipherStr := md5Ctx.Sum(nil)
	return hex.EncodeToString(cipherStr)
}