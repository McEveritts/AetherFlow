package api

import (
	_ "embed"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed spec/openapi-v1.yaml
var openAPISpec []byte

func GetOpenAPISpec(c *gin.Context) {
	c.Data(http.StatusOK, "application/yaml; charset=utf-8", openAPISpec)
}
