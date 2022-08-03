---
title: "Cloud Recon"
date: 2022-08-03T16:18:42-04:00
draft: false
---

Identify the cloud perimeter of a target. Thanks to colleagues who are smarter than me.

### Identify Service

- Is the target on aws, gcp, or azure?
- Download corresponding IP ranges
    - http://ip-ranges.amazonaws.com/ip-ranges.json
    - https://www.gstatic.com/ipranges/cloud.json
    - https://www.microsoft.com/en-us/download/details.aspx?id=56519

### Filter list

- GCP: `jq '.prefixes[] | .ipv4Prefix' -r`
- AWS: `jq '.prefixes[] | .ip_prefix' -r`
- Azure: `jq < /path/to/ServiceTags_Public.*.json '.values | [] | .properties.addressPrefixes | []' -r`
- Ex.
    - `wget https://ip-ranges.amazonaws.com/ip-ranges.json`
    - `cat ip-ranges.json | jq '.prefixes[] | if .region == "us-east-1" then .ip_prefix else empty end' -r | sort -u > ips.txt`

### Create a cloud server

- If your target is in us-east-1 for example, create an EC2 instance in the same region

### Scan

- Use either nmap or masscan to scan for port 443
    - `nmap -p 443 --open iL ips.txt -oA us-east-1_443_scan`
    - `sudo masscan -iL ips.txt -oL us-east-2_443_scan.masscan -p 443 --rate 100000`
- Use tls-scan to collect TLS certificates
    - `cat <file from above> | tls-scan --port 443 --cacert=ca-bundle.crt -o tls_info.json`
- Use `tls_info.json` to find all the IP addresses registered to the target
