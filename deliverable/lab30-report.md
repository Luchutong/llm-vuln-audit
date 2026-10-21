# 实验室 30 题：提示词对照

每行是某一提示词版本在一道题上的判定结果。TP=命中植入类型，FP=误报其他类型，FN=漏报。

| 版本 | 题目 | 类型 | 难度 | 命中 | 误报数 | 漏报 | 报告类型 |
|---|---|---|---|---|---|---|---|
| P0-lite | ch01 | SQL 注入 | 1 | 是 | 0 | 0 | sqli |
| P0-lite | ch02 | 跨站脚本 | 1 | 是 | 0 | 0 | xss |
| P0-lite | ch03 | 命令注入 | 1 | 是 | 0 | 0 | cmdi |
| P0-lite | ch04 | 路径遍历/任意文件读取 | 1 | 是 | 0 | 0 | path_traversal |
| P0-lite | ch05 | 本地文件包含 | 1 | 是 | 0 | 0 | lfi |
| P0-lite | ch06 | 远程文件包含 | 1 | 是 | 1 | 0 | rfi, lfi |
| P0-lite | ch07 | 代码注入 | 1 | 是 | 0 | 0 | code_exec |
| P0-lite | ch08 | 开放重定向 | 1 | 是 | 1 | 0 | open_redirect, auth_bypass |
| P0-lite | ch09 | 敏感信息泄露 | 1 | 否 | 0 | 1 | — |
| P0-lite | ch10 | 弱加密/弱随机 | 1 | 是 | 0 | 0 | weak_crypto |
| P0-lite | ch11 | 跨站脚本 | 2 | 是 | 0 | 0 | xss |
| P0-lite | ch12 | 服务端请求伪造 | 2 | 是 | 0 | 0 | ssrf |
| P0-lite | ch13 | XML 外部实体 | 2 | 是 | 0 | 0 | xxe |
| P0-lite | ch14 | 跨站请求伪造 | 2 | 是 | 1 | 0 | csrf, path_traversal |
| P0-lite | ch15 | 不安全反序列化 | 2 | 是 | 0 | 0 | unserialize |
| P0-lite | ch16 | 越权对象引用 | 2 | 是 | 0 | 0 | idor |
| P0-lite | ch17 | 缺失访问控制 | 2 | 是 | 0 | 0 | broken_access_control |
| P0-lite | ch18 | 认证绕过 | 2 | 是 | 0 | 0 | auth_bypass |
| P0-lite | ch19 | 业务逻辑漏洞 | 2 | 是 | 0 | 0 | business_logic |
| P0-lite | ch20 | 竞争条件 | 2 | 是 | 0 | 0 | race_condition |
| P0-lite | ch21 | 会话固定 | 2 | 是 | 0 | 0 | session_fixation |
| P0-lite | ch22 | 弱类型比较 | 2 | 是 | 0 | 0 | loose_comparison |
| P0-lite | ch23 | SQL 注入 | 3 | 是 | 0 | 0 | sqli |
| P0-lite | ch24 | 命令注入 | 3 | 是 | 0 | 0 | cmdi |
| P0-lite | ch25 | 跨站脚本 | 3 | 是 | 0 | 0 | xss |
| P0-lite | ch26 | 认证绕过 | 3 | 是 | 0 | 0 | auth_bypass |
| P0-lite | ch27 | 不安全反序列化 | 3 | 是 | 0 | 0 | unserialize |
| P0-lite | ch28 | SQL 注入 | 3 | 是 | 0 | 0 | sqli |
| P0-lite | ch29 | 代码注入 | 3 | 是 | 1 | 0 | code_exec, xss |
| P0-lite | ch30 | 缺失访问控制 | 3 | 否 | 2 | 1 | sqli, business_logic |
| P1-lite | ch01 | SQL 注入 | 1 | 是 | 0 | 0 | sqli |
| P1-lite | ch02 | 跨站脚本 | 1 | 是 | 0 | 0 | xss |
| P1-lite | ch03 | 命令注入 | 1 | 是 | 0 | 0 | cmdi |
| P1-lite | ch04 | 路径遍历/任意文件读取 | 1 | 是 | 0 | 0 | path_traversal |
| P1-lite | ch05 | 本地文件包含 | 1 | 是 | 0 | 0 | lfi |
| P1-lite | ch06 | 远程文件包含 | 1 | 是 | 0 | 0 | rfi |
| P1-lite | ch07 | 代码注入 | 1 | 是 | 0 | 0 | code_exec |
| P1-lite | ch08 | 开放重定向 | 1 | 是 | 1 | 0 | open_redirect, auth_bypass |
| P1-lite | ch09 | 敏感信息泄露 | 1 | 是 | 0 | 0 | info_disclosure |
| P1-lite | ch10 | 弱加密/弱随机 | 1 | 是 | 0 | 0 | weak_crypto |
| P1-lite | ch11 | 跨站脚本 | 2 | 是 | 0 | 0 | xss |
| P1-lite | ch12 | 服务端请求伪造 | 2 | 是 | 0 | 0 | ssrf |
| P1-lite | ch13 | XML 外部实体 | 2 | 是 | 0 | 0 | xxe |
| P1-lite | ch14 | 跨站请求伪造 | 2 | 是 | 1 | 0 | csrf, path_traversal |
| P1-lite | ch15 | 不安全反序列化 | 2 | 是 | 0 | 0 | unserialize |
| P1-lite | ch16 | 越权对象引用 | 2 | 是 | 0 | 0 | idor |
| P1-lite | ch17 | 缺失访问控制 | 2 | 是 | 0 | 0 | broken_access_control |
| P1-lite | ch18 | 认证绕过 | 2 | 是 | 1 | 0 | auth_bypass, broken_access_control |
| P1-lite | ch19 | 业务逻辑漏洞 | 2 | 是 | 1 | 0 | business_logic, xss, business_logic |
| P1-lite | ch20 | 竞争条件 | 2 | 是 | 1 | 0 | race_condition, business_logic |
| P1-lite | ch21 | 会话固定 | 2 | 是 | 0 | 0 | session_fixation |
| P1-lite | ch22 | 弱类型比较 | 2 | 是 | 0 | 0 | loose_comparison |
| P1-lite | ch23 | SQL 注入 | 3 | 是 | 0 | 0 | sqli |
| P1-lite | ch24 | 命令注入 | 3 | 是 | 0 | 0 | cmdi |
| P1-lite | ch25 | 跨站脚本 | 3 | 是 | 0 | 0 | xss |
| P1-lite | ch26 | 认证绕过 | 3 | 是 | 0 | 0 | auth_bypass |
| P1-lite | ch27 | 不安全反序列化 | 3 | 是 | 0 | 0 | unserialize |
| P1-lite | ch28 | SQL 注入 | 3 | 是 | 0 | 0 | sqli |
| P1-lite | ch29 | 代码注入 | 3 | 是 | 0 | 0 | code_exec |
| P1-lite | ch30 | 缺失访问控制 | 3 | 否 | 2 | 1 | sqli, business_logic |
| P0 | ch01 | SQL 注入 | 1 | 是 | 0 | 0 | sqli |
| P0 | ch02 | 跨站脚本 | 1 | 是 | 0 | 0 | xss |
| P0 | ch03 | 命令注入 | 1 | 是 | 0 | 0 | cmdi |
| P0 | ch04 | 路径遍历/任意文件读取 | 1 | 是 | 0 | 0 | path_traversal |
| P0 | ch05 | 本地文件包含 | 1 | 是 | 0 | 0 | lfi |
| P0 | ch06 | 远程文件包含 | 1 | 是 | 0 | 0 | rfi |
| P0 | ch07 | 代码注入 | 1 | 是 | 0 | 0 | code_exec |
| P0 | ch08 | 开放重定向 | 1 | 是 | 1 | 0 | open_redirect, auth_bypass |
| P0 | ch09 | 敏感信息泄露 | 1 | 是 | 0 | 0 | info_disclosure |
| P0 | ch10 | 弱加密/弱随机 | 1 | 是 | 1 | 0 | weak_crypto, business_logic |
| P0 | ch11 | 跨站脚本 | 2 | 是 | 0 | 0 | xss |
| P0 | ch12 | 服务端请求伪造 | 2 | 是 | 0 | 0 | ssrf |
| P0 | ch13 | XML 外部实体 | 2 | 是 | 0 | 0 | xxe |
| P0 | ch14 | 跨站请求伪造 | 2 | 是 | 0 | 0 | csrf |
| P0 | ch15 | 不安全反序列化 | 2 | 是 | 0 | 0 | unserialize |
| P0 | ch16 | 越权对象引用 | 2 | 是 | 0 | 0 | idor |
| P0 | ch17 | 缺失访问控制 | 2 | 是 | 0 | 0 | broken_access_control |
| P0 | ch18 | 认证绕过 | 2 | 是 | 0 | 0 | auth_bypass |
| P0 | ch19 | 业务逻辑漏洞 | 2 | 是 | 1 | 0 | business_logic, xss |
| P0 | ch20 | 竞争条件 | 2 | 是 | 1 | 0 | race_condition, business_logic |
| P0 | ch21 | 会话固定 | 2 | 是 | 0 | 0 | session_fixation |
| P0 | ch22 | 弱类型比较 | 2 | 是 | 0 | 0 | loose_comparison |
| P0 | ch23 | SQL 注入 | 3 | 是 | 0 | 0 | sqli |
| P0 | ch24 | 命令注入 | 3 | 是 | 0 | 0 | cmdi |
| P0 | ch25 | 跨站脚本 | 3 | 是 | 0 | 0 | xss |
| P0 | ch26 | 认证绕过 | 3 | 是 | 0 | 0 | auth_bypass |
| P0 | ch27 | 不安全反序列化 | 3 | 是 | 1 | 0 | unserialize, code_exec |
| P0 | ch28 | SQL 注入 | 3 | 是 | 0 | 0 | sqli |
| P0 | ch29 | 代码注入 | 3 | 是 | 0 | 0 | code_exec |
| P0 | ch30 | 缺失访问控制 | 3 | 否 | 0 | 1 | — |
| P1 | ch01 | SQL 注入 | 1 | 是 | 0 | 0 | sqli |
| P1 | ch02 | 跨站脚本 | 1 | 是 | 0 | 0 | xss |
| P1 | ch03 | 命令注入 | 1 | 是 | 0 | 0 | cmdi |
| P1 | ch04 | 路径遍历/任意文件读取 | 1 | 是 | 0 | 0 | path_traversal |
| P1 | ch05 | 本地文件包含 | 1 | 是 | 0 | 0 | lfi |
| P1 | ch06 | 远程文件包含 | 1 | 是 | 1 | 0 | rfi, lfi |
| P1 | ch07 | 代码注入 | 1 | 否 | 1 | 1 | cmdi |
| P1 | ch08 | 开放重定向 | 1 | 是 | 0 | 0 | open_redirect |
| P1 | ch09 | 敏感信息泄露 | 1 | 是 | 1 | 0 | info_disclosure, weak_crypto |
| P1 | ch10 | 弱加密/弱随机 | 1 | 是 | 1 | 0 | weak_crypto, business_logic |
| P1 | ch11 | 跨站脚本 | 2 | 是 | 0 | 0 | xss |
| P1 | ch12 | 服务端请求伪造 | 2 | 是 | 0 | 0 | ssrf |
| P1 | ch13 | XML 外部实体 | 2 | 是 | 0 | 0 | xxe |
| P1 | ch14 | 跨站请求伪造 | 2 | 是 | 1 | 0 | csrf, path_traversal |
| P1 | ch15 | 不安全反序列化 | 2 | 是 | 0 | 0 | unserialize |
| P1 | ch16 | 越权对象引用 | 2 | 是 | 0 | 0 | idor |
| P1 | ch17 | 缺失访问控制 | 2 | 是 | 0 | 0 | broken_access_control |
| P1 | ch18 | 认证绕过 | 2 | 是 | 0 | 0 | auth_bypass |
| P1 | ch19 | 业务逻辑漏洞 | 2 | 是 | 0 | 0 | business_logic |
| P1 | ch20 | 竞争条件 | 2 | 是 | 0 | 0 | race_condition |
| P1 | ch21 | 会话固定 | 2 | 是 | 0 | 0 | session_fixation |
| P1 | ch22 | 弱类型比较 | 2 | 是 | 0 | 0 | loose_comparison |
| P1 | ch23 | SQL 注入 | 3 | 是 | 0 | 0 | sqli |
| P1 | ch24 | 命令注入 | 3 | 是 | 0 | 0 | cmdi |
| P1 | ch25 | 跨站脚本 | 3 | 是 | 0 | 0 | xss |
| P1 | ch26 | 认证绕过 | 3 | 是 | 0 | 0 | auth_bypass |
| P1 | ch27 | 不安全反序列化 | 3 | 是 | 1 | 0 | unserialize, cmdi |
| P1 | ch28 | SQL 注入 | 3 | 是 | 0 | 0 | sqli |
| P1 | ch29 | 代码注入 | 3 | 是 | 0 | 0 | code_exec |
| P1 | ch30 | 缺失访问控制 | 3 | 否 | 3 | 1 | sqli, sqli, business_logic |
| P2 | ch01 | SQL 注入 | 1 | 否 | 0 | 1 | — |
| P2 | ch02 | 跨站脚本 | 1 | 是 | 0 | 0 | xss |
| P2 | ch03 | 命令注入 | 1 | 是 | 0 | 0 | cmdi |
| P2 | ch04 | 路径遍历/任意文件读取 | 1 | 是 | 0 | 0 | path_traversal |
| P2 | ch05 | 本地文件包含 | 1 | 是 | 0 | 0 | lfi |
| P2 | ch06 | 远程文件包含 | 1 | 是 | 0 | 0 | rfi |
| P2 | ch07 | 代码注入 | 1 | 是 | 0 | 0 | code_exec |
| P2 | ch08 | 开放重定向 | 1 | 是 | 0 | 0 | open_redirect |
| P2 | ch09 | 敏感信息泄露 | 1 | 否 | 0 | 1 | — |
| P2 | ch10 | 弱加密/弱随机 | 1 | 是 | 1 | 0 | weak_crypto, business_logic |
| P2 | ch11 | 跨站脚本 | 2 | 是 | 0 | 0 | xss |
| P2 | ch12 | 服务端请求伪造 | 2 | 是 | 0 | 0 | ssrf |
| P2 | ch13 | XML 外部实体 | 2 | 是 | 0 | 0 | xxe |
| P2 | ch14 | 跨站请求伪造 | 2 | 是 | 0 | 0 | csrf |
| P2 | ch15 | 不安全反序列化 | 2 | 否 | 0 | 1 | — |
| P2 | ch16 | 越权对象引用 | 2 | 是 | 0 | 0 | idor |
| P2 | ch17 | 缺失访问控制 | 2 | 是 | 0 | 0 | broken_access_control |
| P2 | ch18 | 认证绕过 | 2 | 是 | 0 | 0 | auth_bypass |
| P2 | ch19 | 业务逻辑漏洞 | 2 | 否 | 0 | 1 | — |
| P2 | ch20 | 竞争条件 | 2 | 否 | 0 | 1 | — |
| P2 | ch21 | 会话固定 | 2 | 否 | 0 | 1 | — |
| P2 | ch22 | 弱类型比较 | 2 | 否 | 0 | 1 | — |
| P2 | ch23 | SQL 注入 | 3 | 是 | 0 | 0 | sqli |
| P2 | ch24 | 命令注入 | 3 | 是 | 0 | 0 | cmdi |
| P2 | ch25 | 跨站脚本 | 3 | 是 | 0 | 0 | xss |
| P2 | ch26 | 认证绕过 | 3 | 是 | 0 | 0 | auth_bypass |
| P2 | ch27 | 不安全反序列化 | 3 | 是 | 0 | 0 | unserialize |
| P2 | ch28 | SQL 注入 | 3 | 是 | 0 | 0 | sqli |
| P2 | ch29 | 代码注入 | 3 | 否 | 0 | 1 | — |
| P2 | ch30 | 缺失访问控制 | 3 | 否 | 0 | 1 | — |

| 版本 | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| P0-lite | 28 | 6 | 2 | 0.824 | 0.933 |
| P1-lite | 29 | 7 | 1 | 0.806 | 0.967 |
| P0 | 29 | 5 | 1 | 0.853 | 0.967 |
| P1 | 28 | 9 | 2 | 0.757 | 0.933 |
| P2 | 21 | 1 | 9 | 0.955 | 0.700 |

> 结论边界：本表是一次顺序运行的描述性结果。30 道题来自同一自建样例集，样本量小、
> 标签经源码核验而非动态 POC 实测，不能据此推断总体准确率或统计显著性。
