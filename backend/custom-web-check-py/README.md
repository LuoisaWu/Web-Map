# Xmap-style 资产测绘脚本（Python 版）

该目录提供 `custom-web-check/xmap-probe.js` 的 Python 等价实现，目标是输出字段、输入方式与整体探测维度保持一致（DNS、端口、HTTP 指纹、SSL 证书、Favicon 哈希）。

## 运行方式

要求：Python 3.9+（仅使用标准库，无需额外安装依赖）

进入本目录后执行：

```bash
python xmap_probe.py -h
```

## 常用示例

单目标：

```bash
python xmap_probe.py -t example.com -o result.csv
```

IP + 虚拟主机（Host/SNI）：

```bash
python xmap_probe.py -t 1.2.3.4 --host-header example.com --sni example.com -o result.csv
```

批量文件（TXT/CSV）：

```bash
python xmap_probe.py -f ..\\top-1m.csv -c 100 --ports 80,443,8080,8443 -o results_batch.csv
```

管道流式输入：

```bash
type targets.txt | python xmap_probe.py -c 50 -o results_stream.csv
```

## 输出格式

严格输出 22 列 CSV（与 Node 版一致）：

`Rank,Domain,IP_A,IP_AAAA,DNS_CNAME,DNS_MX,DNS_TXT,DNS_NS,Open_Ports,Favicon_Hash,HTTP_Status,Title,Server,X_Powered_By,WAF_Detect,Via_Proxy,Set_Cookie,HSTS,SSL_Issuer,SSL_Subject,SSL_Valid_From,SSL_Valid_To`

