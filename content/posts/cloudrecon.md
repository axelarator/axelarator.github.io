---
title: "Cloud Recon"
date: 2022-08-03T16:18:42-04:00
draft: False
---

Identify the cloud perimeter of a target. Thanks to colleagues who are smarter than me.

### Identify Service

- Use OSINT to determine the provider and region your target is located in.
    - Shodan for example has a `cloud.region` filter that lists what region the IP is located in. Some examples:
        - GCP: us-central1
        - Azure: northeurope
        - AWS: us-east-1
- Download corresponding IP ranges based on your target’s provider.
    - https://ip-ranges.amazonaws.com/ip-ranges.json
    - https://www.gstatic.com/ipranges/cloud.json
    - https://www.microsoft.com/en-us/download/details.aspx?id=56519

### Filter list

- GCP: `jq '.prefixes[] | .ipv4Prefix' -r`
- AWS: `jq '.prefixes[] | .ip_prefix' -r`
- Azure: `jq '.values[] | .properties.addressPrefixes[]' -r`
- Ex.
    - `wget https://ip-ranges.amazonaws.com/ip-ranges.json`
    - `cat ip-ranges.json | jq '.prefixes[] | if .region == "us-east-1" then .ip_prefix else empty end' -r | sort -u > ips.txt`

### Create a cloud server

- If your target is in us-east-1 for example, create an EC2 instance in the same region.
- Don’t need to get fancy with it. A free tier will do.
- Download `nmap` `masscan` `tls-scan` and `jq`

### Scan

- Use either nmap or masscan to scan for port 443 on the filtered file.
- Go get something to eat or touch grass while this runs.
- `nmap -p 443 --open iL ips.txt -oA us-east-1_443_scan`
- `sudo masscan -iL ips.txt -oL us-east-2_443_scan.masscan -p 443 --rate 100000`
- Use tls-scan to collect TLS certificates
    - `cat <file from above> | tls-scan --port 443 --cacert=ca-bundle.crt -o tls_info.json`
- Filter `tls_info.json` to find all the IP addresses registered to the target.
    - `cat tls_info.json | jq 'select(.host | contains("<ip>")) | .host, .certificateChain[]'`
    - `<ip>` above could be a complete IP or maybe just the network part like `192.168` if you want to filter for all subnets in that network range.