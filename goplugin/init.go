package goplugin

import (
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"
	"github.com/opensec-cn/kunpeng/util"
	// "fmt"
)

var (
	client   *http.Client
	PassList []string
	Aider    string
)

func init() {
	client = util.Client
	PassList = []string{
		"{user}", "{user}123", "admin", "123456", "",
	}
}


func getRandomString(l int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyz"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}
func inArray(list []string, value string, regex bool) bool {
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
func aiderCheck(randStr string) bool {
	request, _ := http.NewRequest("GET", Aider+"/check/"+randStr, nil)
	resp, err := util.RequestDo(request, true)
	if err != nil {
		return false
	}
	if strings.Contains(resp.ResponseRaw, "VUL00") {
		return true
	}
	return false
}
