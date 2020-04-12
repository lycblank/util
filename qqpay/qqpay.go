package qqpay

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"github.com/parnurzeal/gorequest"
	"io"
	"io/ioutil"
	mrand "math/rand"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

var DefaultPay = &QQPay{}

var QQPayUrl = `https://api.qpay.qq.com/cgi-bin/epay/qpay_epay_b2c.cgi`
type QQPay struct {
	AppId string
	OpUserId string
	OpUserPasswd string
	MchId string
	SpbillCreateIp string // 调用接口ip地址
	NotifyUrl string
	Key string

	KeyFile string
	CertFile string
	RootCa string
}

// 参照 https://qpay.qq.com/buss/wiki/206/1215
type QQPayArg struct {
	XMLName    xml.Name   `xml:"xml"`
	InputCharset string   `xml:"input_charset"`
	Openid string         `xml:"openid"`
	OutTradeNo string     `xml:"out_trade_no"`
	TotalFee int          `xml:"total_fee"`
	AppId string          `xml:"appid"`
	OpUserId string       `xml:"op_user_id"`
	OpUserPasswd string   `xml:"op_user_passwd"`
	MchId string          `xml:"mch_id"`
	SpbillCreateIp string `xml:"spbill_create_ip"` // 调用接口ip地址
	//NotifyUrl string      `xml:"notify_url"`
	NonceStr string 	  `xml:"nonce_str"`
	FeeType string 		  `xml:"fee_type"`
	Sign string 		  `xml:"sign"`
}

type QQPayResp struct {
	XMLName    xml.Name   `xml:"xml"`
	RetCode string    		`xml:"retcode"`
	RetMsg string 			`xml:"retmsg"`
	TransactionId string `xml:"transaction_id"`
	ErrCodeDesc string `xml:"err_code_desc"`
}

type TransMoneyResp struct {
	OutTradeNo string
	TransactionId string
}

func TransMoney(openid string, money int) (resp TransMoneyResp, err error) {
	return DefaultPay.TransMoney(openid, money)
}

func (p *QQPay) TransMoney(openid string, money int) (resp TransMoneyResp, err error) {
	arg := &QQPayArg{
		InputCharset:"UTF-8",
		FeeType:"CNY",
		AppId:p.AppId,
		Openid:openid,
		MchId:p.MchId,
		NonceStr:"123",//GetNotifyStr(),
		TotalFee:money,
		OpUserId:p.OpUserId,
		OpUserPasswd:p.OpUserPasswd,
		SpbillCreateIp:p.SpbillCreateIp,
		//NotifyUrl:p.NotifyUrl,
		OutTradeNo: GetOutTradeNo(),
	}
	arg.Sign = p.GenSign(arg)
	datas, err := xml.Marshal(arg)
	if err != nil {
		return
	}
	fmt.Println(string(datas))
	request := gorequest.New().Post(QQPayUrl)
	request.Debug = true
	request.SendString(string(datas))
	request.Transport = GetTransport(p.KeyFile, p.CertFile, p.RootCa)
	request.Header.Set(`Content-Type`, `application/xml`)
	_, body, errs := request.EndBytes()
	if len(errs) > 0 {
		err = errs[0]
		return
	}

	qqResp := &QQPayResp{}
	err = xml.Unmarshal(body, &qqResp)
	if err != nil {
		return
	}
	fmt.Println(qqResp)

	/*if qqResp.ReturnCode != "SUCCESS" {
		err = errors.New(qqResp.ErrCodeDesc)
		return
	}*/

	resp.OutTradeNo = arg.OutTradeNo
	resp.TransactionId = qqResp.TransactionId
	return
}
func (p *QQPay) GenSign(arg *QQPayArg) string {
	v := map[string]string{
		"fee_type":arg.FeeType,
		"input_charset": arg.InputCharset,
		"openid":arg.Openid,
		"out_trade_no":arg.OutTradeNo,
		"total_fee":strconv.Itoa(arg.TotalFee),
		"appid": arg.AppId,
		"op_user_id": arg.OpUserId,
		"op_user_passwd": arg.OpUserPasswd,
		"mch_id": arg.MchId,
		"spbill_create_ip":arg.SpbillCreateIp,
//		"notify_url": arg.NotifyUrl,
		"nonce_str": arg.NonceStr,
	}

	var buf strings.Builder
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := v[k]
		if buf.Len() > 0 {
			buf.WriteByte('&')
		}
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(v)
	}
	buf.WriteString("&key=")
	buf.WriteString(p.Key)
	h := md5.New()
	io.WriteString(h, buf.String())
	return fmt.Sprintf("%X", h.Sum(nil))
}


func GetNotifyStr() string {
	datas := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, datas)
	if err != nil {
		datas = []byte(fmt.Sprintf("%d.%d", time.Now().UnixNano(), mrand.Int63()))
	}
	h := md5.New()
	h.Write(datas)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func GetOutTradeNo() string {
	datas := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, datas)
	if err != nil {
		datas = []byte(fmt.Sprintf("%d.%d", time.Now().UnixNano(), mrand.Int63()))
	}
	h := md5.New()
	h.Write(datas)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func GetTransport(key,cert string, ca string) *http.Transport {
	certs, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil
	}
	rootCa, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootCa)
	tr := &http.Transport{
		TLSClientConfig:&tls.Config{
			RootCAs:pool,
			Certificates:[]tls.Certificate{certs},
			InsecureSkipVerify:true,
		},
	}
	return tr
}





