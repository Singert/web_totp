package main

import (
	"bufio"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

func readSecret() (string, error) {
	data, err := os.ReadFile(".Base32")
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(strings.TrimSpace(string(data)), "-", ""), nil
}

func isKeyAllowed(inputKey string) bool {
	file, err := os.Open("keylist")
	if err != nil {
		log.Println("读取 keylist 出错：", err)
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == inputKey {
			return true
		}
	}
	return false
}

func logAccess(key, code, ip, ua string) {
	t := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] key=%s code=%s ip=%s ua=%q\n", t, key, code, ip, ua)
	f, err := os.OpenFile("access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("日志写入失败：", err)
		return
	}
	defer f.Close()
	f.WriteString(logLine)
}

func main() {
	router := gin.Default()
	router.SetFuncMap(template.FuncMap{"now": time.Now})
	router.LoadHTMLGlob("templates/*")

	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "form.tmpl", gin.H{})
	})

	router.POST("/", func(c *gin.Context) {
		key := c.PostForm("key")
		if !isKeyAllowed(key) {
			c.HTML(http.StatusUnauthorized, "form.tmpl", gin.H{
				"Error": "访问 key 不正确",
			})
			return
		}

		secret, err := readSecret()
		if err != nil {
			c.String(http.StatusInternalServerError, "读取密钥失败")
			return
		}

		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			c.String(http.StatusInternalServerError, "生成验证码失败")
			return
		}

		remain := 30 - time.Now().Unix()%30
		ip := c.ClientIP()
		ua := c.GetHeader("User-Agent")
		logAccess(key, code, ip, ua)
		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/code?code=%s&remain=%d&key=%s", code, remain, key))
	})

	router.GET("/code", func(c *gin.Context) {
		code := c.Query("code")
		remain := c.Query("remain")
		key := c.Query("key")
		ip := c.ClientIP()
		ua := c.GetHeader("User-Agent")
		logAccess(key, code, ip, ua)
		c.HTML(http.StatusOK, "code.tmpl", gin.H{
			"Code":   code,
			"Remain": remain,
		})
	})

	router.GET("/code/auto", func(c *gin.Context) {
		key := c.Query("key")
		if !isKeyAllowed(key) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		secret, err := readSecret()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "read secret failed"})
			return
		}
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "generate code failed"})
			return
		}
		remain := 30 - time.Now().Unix()%30
		ip := c.ClientIP()
		ua := c.GetHeader("User-Agent")
		logAccess(key, code, ip, ua)
		c.JSON(http.StatusOK, gin.H{
			"code":   code,
			"remain": remain,
		})
	})

	log.Println("服务已启动：http://localhost:8089/")
	router.Run(":8089")
}
