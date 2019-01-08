package web

import "github.com/gin-gonic/gin"
import "github.com/opensec-cn/kunpeng/plugin"
import "net/http"
// import "fmt"


// StartServer 启动web服务接口
func StartServer(){
	router := gin.Default()
	router.GET("/api/pluginList", func(c *gin.Context) {
		c.JSON(200, plugin.GetPlugins())
	})
	router.POST("/api/:type/:target", func(c *gin.Context) {
		t := c.Param("type")
		target := c.Param("target")
		var json plugin.TaskInfo
		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		json.Target = target
		json.Type = t
		_, result := plugin.Scan(json)
		c.JSON(200, result)
	})
	
	router.Run(":38080")
}