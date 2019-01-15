package web

import (
	"github.com/gin-gonic/gin"
	"github.com/opensec-cn/kunpeng/plugin"
	"github.com/opensec-cn/kunpeng/config"
	"net/http"
)
// import "fmt"


// StartServer 启动web服务接口
func StartServer(){
	router := gin.Default()
	router.GET("/api/pluginList", func(c *gin.Context) {
		c.JSON(200, plugin.GetPlugins())
	})
	router.POST("/api/check", func(c *gin.Context) {
		var json plugin.TaskInfo
		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		result := plugin.Scan(json)
		c.JSON(200, result)
	})
	router.POST("/api/config", func(c *gin.Context) {
		buf := make([]byte, 2048)
		n, _ := c.Request.Body.Read(buf)
		config.Set(string(buf[0:n]))
		c.JSON(200, map[string]bool{"success":true})
	})
	
	router.Run(":38080")
}