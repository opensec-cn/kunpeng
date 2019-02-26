// Package web 提供webapi接口调用
package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/opensec-cn/kunpeng/config"
	"github.com/opensec-cn/kunpeng/plugin"
)

// StartServer 启动web服务接口
func StartServer(bindAddr string) {
	router := gin.Default()
	router.GET("/api/pluginList", func(c *gin.Context) {
		c.JSON(200, plugin.GetPlugins())
	})
	router.POST("/api/check", func(c *gin.Context) {
		var json plugin.Task
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
		c.JSON(200, map[string]bool{"success": true})
	})

    router.GET("/pluginList",func(c *gin.Context) {
        c.Header("Content-type","text/html;charset=utf-8")
        c.String(200,`
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8" />
        <title>北冥有鱼，其名为鲲</title>
        <meta name="description" content="" />
    </head>
    <body>
        <link href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet" />
        <script src="//cdn.bootcss.com/jquery/1.11.1/jquery.js"></script>
        <link href="//cdn.datatables.net/1.10.19/css/dataTables.bootstrap.min.css" rel="stylesheet" />
        <link href="//cdn.datatables.net/1.10.19/css/dataTables.bootstrap.min.css" rel="stylesheet" />
        <script src="//cdn.datatables.net/1.10.19/js/jquery.dataTables.min.js"></script>
        <script src="//cdn.datatables.net/1.10.19/js/dataTables.bootstrap.min.js"></script>
        <div class="panel panel-default"> 
            <div class="panel-heading">鲲之大，不知其几千里也! 如果列表为空，可能cdn资源没有加载到，请检查网络</div> 
            <div class="panel-body">
                <table id="pluginListTable" class="table table-striped table-bordered" > 
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>author</th>
                                <th>remarks</th>
                                <th>target</th>
                            </tr>
                        </thead>
                </table>
            </div>
        </div>
        <script>
            $(function(){
                $("#pluginListTable").DataTable({
                    "pageLength":25,
                    "ajax":{
                        "url":"/api/pluginList",
                        "dataSrc":""
                    },
                    "columns":[
                        {"data":"name"},
                        {"data":"author"},
                        {"data":"remarks"},
                        {"data":"target"}
                    ]
                });
            });
        </script>
    </body>
</html>
        `) 
    })

	router.Run(bindAddr)
}
