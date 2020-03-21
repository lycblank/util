package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/parnurzeal/gorequest"
	"regexp"
	"time"
)

var CODE_SESSION_URL = `https://api.q.qq.com/sns/jscode2session`
var GET_ACCESS_TOKEN = `https://api.q.qq.com/api/getToken`
var CREATE_MINI_CODE = `https://api.q.qq.com/api/json/qqa/CreateMiniCode`

type qqMiniProgram struct {
	appid string
	secret string
	accessToken string
	expireTime int64
}

func NewQQMiniProgram(appid, secret string) *qqMiniProgram {
	qq := &qqMiniProgram{
		appid:appid,
		secret:secret,
	}
	return qq
}

type Code2SessionResp struct{
	Openid string     `json:"openid"`
	SessionKey string `json:"session_key"`
	Unionid string    `json:"unionid"`
	//-1	系统繁忙，此时请开发者稍候再试
	//0	请求成功
	//40029	code 无效
	//45011	频率限制，每个用户每分钟100次
	//-101222100	参数错误，请检查appid和appsecret是否正确,请检查ide上创建工程用的appid是否正确
	Errcode int64     `json:"errcode"`
	Errmsg string     `json:"errmsg"`
}
// 参照https://q.qq.com/wiki/develop/miniprogram/server/open_port/port_login.html
func (qq *qqMiniProgram) Code2Session(code string) (sessionKey string, openId string, err error) {
	request := gorequest.New().Get(CODE_SESSION_URL)
	request.Debug = true
	request = request.Param("appid", qq.appid)
	request = request.Param("secret", qq.secret)
	request = request.Param("js_code", code)
	request = request.Param("grant_type", "authorization_code")
	resp := &Code2SessionResp{}
	_, _, errs := request.EndStruct(resp)
	if len(errs) > 0 {
		err =  errs[0]
		return
	}
	if resp.Errcode != 0 {
		err =  errors.New(resp.Errmsg)
		return
	}

	openId = resp.Openid
	sessionKey = resp.SessionKey
	return
}

type AccessTokenResp struct {
	AccessToken string `json:"access_token"`
	ExpiresIn int64    `json:"expires_in"`
	Errcode int32      `json:"errcode"`
	Errmsg string      `json:"errmsg"`
}

// 参照https://q.qq.com/wiki/develop/miniprogram/server/open_port/port_use.html#getaccesstoken
func (qq *qqMiniProgram) GetAccessToken() (err error) {
	request := gorequest.New().Get(GET_ACCESS_TOKEN)
	request.Debug = true
	request.Param("grant_type", "client_credential")
	request.Param("appid", qq.appid)
	request.Param("secret", qq.secret)

	r := &AccessTokenResp{}
	_, _, errs := request.EndStruct(r)
	if len(errs) > 0 {
		err = errs[0]
		return
	}
	qq.accessToken = r.AccessToken
	qq.expireTime = r.ExpiresIn + time.Now().Unix()
	return
}

func (qq *qqMiniProgram) CreateMiniCode(path string) (imageBuff []byte, err error) {
	nowTime := time.Now().Unix()
	if qq.expireTime <= nowTime {
		err = qq.GetAccessToken()
		if err != nil {
			return
		}
	}
	request := gorequest.New().Post(CREATE_MINI_CODE)
	request.Debug = true
	request.Param("access_token", qq.accessToken)
	body := map[string]interface{}{
		"access_token": qq.accessToken,
		"appid": qq.appid,
		"path": path,
	}
	_, datas, errs := request.SendMap(body).EndBytes()
	if len(errs) > 0 {
		err = errs[0]
		return
	}
	imageBuff = datas
	return
}


// https://q.qq.com/wiki/develop/miniprogram/frame/open_ability/open_userinfo.html
func (qq *qqMiniProgram) Decrypt(encryptedData, iv string, sessionKey string) (map[string]interface{}, error) {
	if len(sessionKey) != 24 {
		return nil, errors.New("sessionKey length is error")
	}
	aesKey, err := base64.StdEncoding.DecodeString(sessionKey)
	if err != nil {
		return nil, err
	}

	if len(iv) != 24 {
		return nil, errors.New("iv length is error")
	}
	aesIV, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil,  err
	}

	aesCipherText, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}
	aesPlantText := make([]byte, len(aesCipherText))

	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(aesBlock, aesIV)
	mode.CryptBlocks(aesPlantText, aesCipherText)
	aesPlantText = PKCS7UnPadding(aesPlantText)

	var decrypted map[string]interface{}

	re := regexp.MustCompile(`[^\{]*(\{.*\})[^\}]*`)
	aesPlantText = []byte(re.ReplaceAllString(string(aesPlantText), "$1"))

	err = json.Unmarshal(aesPlantText, &decrypted)
	if err != nil {
		return nil,  err
	}
	return decrypted, nil
}

// PKCS7UnPadding return unpadding []Byte plantText
func PKCS7UnPadding(plantText []byte) []byte {
	length := len(plantText)
	if length > 0 {
		unPadding := int(plantText[length-1])
		return plantText[:(length - unPadding)]
	}
	return plantText
}
