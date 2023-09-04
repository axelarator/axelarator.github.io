---
title: "Hunting C2s with Nuclei"
date: 2023-09-04T14:55:00-06:00
draft: false
---

# Overview

For a long time now, I’ve been using Censys/Shodan and DomainTools to look up hosts, attempt to correlate infrastructure to find overlaps and potentially attribute to C2s and other malicious hosts. There are so many data points to look at like JARM signatures, certificate data including historical analysis to watch hosting changes, service commonalities including the same web server hosted across multiple IPs, subdomains, etc. My point is this process almost always requires manual intervention at least first to visualize a pattern, then you can automate the infrastructure hunting for real-time monitoring. My next goal was to somehow automate these checks.

# Hunting Scenarios

I’ve had luck in the past when using response banners to uncover malicious infrastructure. Taking inspiration from this [post](https://sh1ttykids.medium.com/new-techniques-uncovering-tor-hidden-service-with-etag-5249044a0e9d), I could not replicate the author’s findings using Etag due to the post being three years old and since publication, the ransomware operator also being [indicted](https://www.justice.gov/opa/pr/russian-national-charged-ransomware-attacks-against-critical-infrastructure). As an alternative, I copied the response from the onion site. 

### RagnarLocker Hunting

- Gather banner from ransomware leak site’s response header. Below can be copied into Censys.
    - services.banner="HTTP/1.1 404 Not Found\r\nServer: nginx/1.14.1\r\nDate: \<REDACTED>\r\nContent-Type: text/html; charset=UTF-8\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Powered-By: PHP/7.2.24\r\n”
- First is to look for / test `E-Tag` values but if nothing, query entire response body banner.
    - If the resource at a given URL changes, a new `E-tag` value *must* be generated.
- IP: 45.136.199.200
    - VT pivoting on IPs in the same network shows `45.136.196.154` distributing RedLine stealer
    - FIN7 IP `45.136.199.128` specifically the DICELOADER C2
        - [https://labs.withsecure.com/publications/fin7-target-veeam-servers](https://labs.withsecure.com/publications/fin7-target-veeam-servers)
- IP: 47.103.82.193
    - Interesting favicon hash: `http.favicon.hash:378596000`
    - Cert: 18ebc8102265014e320b6ebc540fb65444c3174abca8bcc9757a0dd7a46bf803
    - Pivoting off above cert: 47.101.213.146
        - JARM: 2ad2ad0002ad2ad00042d42d0000005d86ccb1a0567e012264097a0315d7a7

Unrelated to banners, if I were to just do a simple query for “Nimplant C2 Server”, I’d get (as of writing this now) seven hosts. Not bad, but something tells me more are out there. So how do you hunt for the unknown? Look for commonalities across hosts. Here are a few for Nimplant:

### NimPlant Hunting

- Shodan: `http.html_hash:-1258014549`
    - This is a hash calculated from all the data within the banner.
        - Going back to the RagnarLocker hunting, if your search is based on that specific banner, it’d be easier to search for the `html_hash` of `-1207101977`.
    - HTML hashes aren’t exclusive and their results shouldn’t conclude 100% accuracy as there is a high FP rate, but it’s a good starting point to narrow results.
    - One host I found had their directory public and a text file linking to a domain
        - `http://195.140.214.108/reds/config/`
        - `brokendreams.online/tomo/n3vr/dice.php` returns a 403 access denied.
- Look at status codes and ports. The default port for NimPlant servers is 80 or 31337 and listeners on 443. Those on 443 usually return a 404 with a response body of `{status":"Not found"}`
    - [https://github.com/chvancooten/NimPlant/blob/cbac6055c0640f216a6056b8699198c9771c9b96/README.md?plain=1#L168](https://github.com/chvancooten/NimPlant/blob/cbac6055c0640f216a6056b8699198c9771c9b96/README.md?plain=1#L168)
- That link brings me to my next point. If the C2 you’re hunting for is open-sourced, search its repo on GitHub to find default values, common configurations, even use it yourself and capture traffic.
- `Server: NimPlant C2 Server`
    - This is the easiest way to hunt for default C2s as poor OPSEC leads users to forget to change default configs.
- `Content-Length: 23`
    - It seems all headers have the same length.

I could go on but the point is this is a good example of how a minor amount of OSINT can uncover malicious hosts. This only works well in one direction though; when querying the open internet. I could build out a very lengthy Censys query using conditionals, order of operations, and run that on a automated schedule. What if we receive 100 IPs and need to attribute those? The above method is still applicable, but not everything in that query may match. You’ll have to start using multiple queries when going between hosts and certificates since Censys differentiates those queries with either `/hosts/` or `/certificates/`. Modifying queries on large datasets can lead to many errors and false positives/negatives.

Enter Nuclei

# Nuclei

Nuclei is marketed primarily as a tool for pen testers, bug bounty hunters, appsec folks, etc. It’s a scanner written in Go designed to scan applications, infrastructure, cloud environments and networks to help find and remediate vulnerabilities. The core of Nuclei relies on templates. These are YAML files where you specify a potential attack vector or fingerprinting during a reconnaissance stage. Examples can be looking for CVEs, anonymous login, weak cipher suites, self-signed certs, the list keeps going. 

These templates can even be chained together. If you have 500 IPs and want to find a specific CVE, you create what’s called a “workflow”. An example they provide is running a template that looks for BigIP configuration utility hosts, then for all hosts matching that template, it runs another template looking for CVE-2020-5902. 

## Using Templates

I focused on Nimplant for testing because I already had data to validate when testing templates. I made three separate templates as it’s good practice to separate templates based on what kind of request you’re making as to not overcomplicate them. Think of these templates like YARA rules. Rather than looking for file samples, we’re looking for specific hosts.

This first one uses an HTTP GET request and matches on content-length, looking for specific server headers, and status codes of either 404 or 500. I included three different matchers grouped by an AND operator so I only get hosts that match all three.

Sidenote: DSL is an engine that provides a set of helper functions. 

- [https://github.com/projectdiscovery/dsl](https://github.com/projectdiscovery/dsl)

### Nimplant C2 Template

```yaml
id: nimplant-c2

info:
    name: Uncover Nimplant C2 Servers
    author: Taylor
    severity: low
    description: Searches for a specific content-length, server header, and status codes.
    reference: Knowledge
    tags: c2, http

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: dsl
        name: content-length
        dsl:
          - "content_length == 23"

      - type: word
        name: nimplant
        words: 
          - "NimPlant C2 Server"
          - "Apache/2.4.29 (Ubuntu)"
        condition: or
        part: header

      - type: status
        name: status
        status: 
          - 404
          - 500
        condition: or
```

![Untitled](/hunt/Untitled.png)

### Nimplant SSL Template

This is where templates get a bit complex and I’ll introduce workflows. Nimplant servers used to use self-signed certs with `issuer_cn: operator` and `subject_cn: multiplayer` but that has since changed. What I’ve noticed now is they’re using valid certificates signed by Let’s Encrypt with `subject_cn` values containing the resolved domain. For example, `123.456.789.100` resolves to `domain.com` and `domain.com` is also the value of `subject_cn`. I wanted to write a rule that finds any certs matching this condition. The difficulty was I needed a way to resolve a host, save it somewhere and use it within another helper function. If I understand correctly, until multi protocol support is added, these checks need to be in separate templates which is fine because Nuclei uses extractors. Extractors can be used to extract and display results in a match from the response returned by a module. 

Luckily, a template already exists within the SSL folder called `ssl-dns-names.yaml` which takes a host:port as input and extracts the `.subject_an[]`. The dot is because extractors with a `type: json` use Jquery syntax to format output. 

I modified the below template to include `name: extracted_san` so I can use that value elsewhere. 

```yaml
id: ssl-dns-names

info:
  name: SSL DNS Names
  author: pdteam
  severity: info
  description: |
    Extract the Subject Alternative Name (SAN) from the target's certificate. SAN facilitates the usage of additional hostnames with the same certificate.
  tags: c2,ssl,dns,nimplant
  metadata:
    max-request: 1

ssl:
  - address: "{{Host}}:{{Port}}"

    extractors:
      - type: json
        name: extracted_san
        json:
          - ".subject_an[]"
```

![Untitled](/hunt/Untitled%201.png)

Since the above extractor has a name and is now a variable, it can be referenced directly in the DSL helper function. The `matchers-condition` is set to OR because this template needs to both be self sufficient and work within a workflow. The reason being is the first matcher will only work when run after `ssl-dns-names` because it takes a passed variable as input to the contains() function. If you were to run this by itself, that matcher would always fail. So another pattern I noticed within the certificate is they all contain a `mismatched: true` pair. 

The contains() function works like you’d think. It verifies if a string contains a substring. So in this case, I’m checking if “officemobsync[.]com” (subject_cn) is within “officemobsync[.]com” (extracted_san). 

As an output, I decided to include the `subject_cn` and value of `mismatched`. 

```yaml
id: nimplant-c2-ssl

# Uses extractor to take subject_cn from ssl/ssl-dns-names.yaml
# Input variable here to match subject_cn of cert to domain name
# https://docs.nuclei.sh/template-guide/workflows

info:
    name: Nimplant SSL Discovery
    author: axelarator
    severity: low
    description: Finding Nimplant C2 servers based on SSL attributes
    reference: blank for now
    tags: c2,nimplant,ssl

ssl:
  - address: "{{Host}}:{{Port}}"
    matchers-condition: or
    matchers:
      - type: dsl
        name: contains
        dsl:
          - contains(extracted_san, subject_cn)

      - type: dsl
        name: mismatch
        dsl:
          - "mismatched == true"
    
    extractors:
      - type: json
        name: host
        json:
          - ".subject_cn, .mismatched"
```

I mentioned I’d introduce workflows. They’re actually very simple and only require a few lines of code. The `-w` flag is for workflows while `-t` is for templates. As I’m taking a value from one and passing to another, the second template is defined as a subtemplate. Nuclei calls this a “shared execution context”. The template:subtemplate pairs can be stacked into a hierarchal tree for numerous conditional matchings too. 

```yaml
id: nimplant-workflow

info: 
  name: nimplant-workflow
  author: axelarator
  severity: info
  description: takes resolved DNS name to compare to certificate subject_cn value

workflows:
  - template: ssl/ssl-dns-names.yaml
    subtemplates:
      - template: nimplant-c2-ssl.yaml
```

![Untitled](/hunt/Untitled%202.png)

Workflows don’t require subtemplates. Instead, you could add different groups of templates or even tags specified in each template. Here’s an example they share:

```yaml
workflows:
  - template: cves/
  - template: exposed-tokens/
  - template: exposures/
  - tags: exposures
```

### Nimplant JARM Template

Lastly, this one is very simple. I send some hex data to a server in order to get a response and complete the handshake process for calculating a JARM signature. Again, using a DSL helper function `jarm`, I can match the calculated signature. 

A quick way to calculate a JARM is pass the host:port to tlsx. This is how the helper function in the code block below works.

![Untitled](/hunt/Untitled%203.png)

```yaml
id: nimplant-c2-jarm

info:
  name: Nimplant C2 JARM - Detect
  author: axelarator
  severity: info
  description: Calculating the JARM and comparing it to a known Nimplant JARM signature
  reference:
    - https://github.com/cedowens/C2-JARM
    - https://github.com/chvancooten/NimPlant
  tags: c2,ir,osint,nimplant,jarm

tcp:
  - inputs:
      - data: 2E
        type: hex

    host:
      - "{{Hostname}}"

    matchers:
      - type: dsl
        dsl:
          - "jarm(Hostname) == '28d28d28d00028d00042d42d000000ad9bf51cc3f5a1e29eecb81d0c7b06eb'"
```

Both outputs below achieve the same effect. Due to how the hostname is formatted, a port is required. The first option is fine if you know the host is running an HTTPS service on a specific port. 

![Untitled](/hunt/Untitled%204.png)

This option is useful if you’re unsure what ports the HTTPS service(s) may be running on. Running tlsx on it’s own, you see it found a service on 443. 

![Untitled](/hunt/Untitled%205.png)

I can use the output from tlsx, pipe it to nuclei and run against the JARM template.

![Untitled](/hunt/Untitled%206.png)

# No IPs? No Problem

Running against a collected list of hosts has a more clear scope as there’s already some defined correlation about where the IPs came from. But what if your focus isn’t on IPs. Maybe it’s a suspicious certificate? I find myself pivoting on certs a lot as they can uncover shared hosts. Using another tool, [Uncover](https://github.com/projectdiscovery/uncover), it eases the need to create separate API requests, dump the data, then query further on Nuclei or other tools. For my example, I’m taking a certificate fingerprint from a cert with a subject_cn of multiplayer. This was also a tactic Sliver C2s used.

- 7eb6defb76a241bfb20d19837bb46276cbd368e18b0c463aa5a1f181d0bfad75

I supplied a Censys query that searches for any other hosts using this cert and piped it to Nuclei without any template definition to see what it could uncover about the hosts. Unfortunately, only one host is using it but that’s ok. 

![Untitled](/hunt/Untitled%207.png)

It matched some of my rules along with some default ones. Since I knew Nimplant ****used**** to use multiplayer as their subject_cn, I checked VT just as a sanity check and look at that, it’s actually a Sliver C2.

- [https://www.virustotal.com/gui/ip-address/138.197.36.34/community](https://www.virustotal.com/gui/ip-address/138.197.36.34/community)

# Conclusion

This threat hunting workflow can make it very easy to quickly identify some malicious hosts without navigating through multiple products, defining long queries and manual review of individual hosts. I only created some basic templates for now to learn Nuclei, but if you read the docs, templates can get increasingly complex. My goal with this is an easy to use and fully customizable hunt workflow without needing enterprise licenses or other paid services. The tools I used are all from [ProjectDiscovery](https://github.com/projectdiscovery). For Uncover, the only values supplied were my Censys and Shodan API keys. 

- [https://github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)
- [https://github.com/projectdiscovery/uncover](https://github.com/projectdiscovery/uncover)
- [https://github.com/projectdiscovery/tlsx](https://github.com/projectdiscovery/tlsx)
- [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

# Resources

- [Cobalt Strike Hunting](https://michaelkoczwara.medium.com/cobalt-strike-hunting-aefe1c5d1ec5)
- [Uncovering Tor Hidden Services with Etag](https://sh1ttykids.medium.com/new-techniques-uncovering-tor-hidden-service-with-etag-5249044a0e9d)
- [Hunting C2 Servers](https://blog.projectdiscovery.io/hunting-c2-servers/)