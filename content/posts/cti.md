---
title: "The A in CTI Stands for Actionable"
date: 2024-04-13T12:43:45-06:00
draft: false
---

# CTI

Cyber Threat Intelligence is about communicating the latest information on threat actors and incidents to organizations in a timely manner. Analysis in these areas allows an organization to maintain situational awareness of the current threat landscape, organizational impacts, and threat actor motives. The level of information that needs to be conveyed is dependent on specific teams within CTI as specific levels on granularity depends on who you're speaking to. There are three types of threat intelligence teams: Tactical, Operational, and Strategic. Verbiage throughout organizations may differ but the ideology remains the same.

Tactical handles ingesting threat indicators into defensive cybersecurity solutions. Data from which can include hashes, IPs, phishing domains, etc. This is a collection of raw data prior to distillation personalization that can be ingested into a SOC platform for alerting purposes.

Operational threat intelligence focuses on threat actor behavior that describes who the actors target, why, and how. As I work within the operational space, my area of focus surrounds threat actor campaigns and emerging trends to provide intel the company can use to build out defenses. The resulting data from this kind of work is used to uncover attack patterns, adversary infrastructure, capabilities, and provide guidance around protecting against related activity in the future. A way to visualize this data would be to use the Diamond Model as it clearly lays out details about the adversary, infrastructure, tradecraft, and victims.

![Untitled](/cti/diamond.png)
> Diamond Model of IcedID's latest intrusion - TheDFIRReport

Strategic focuses on discussing the overall threat landscape using trends, geopolitical events, and emerging risks to help businesses maintain their security posture. An example could be giving a briefing on the mobile threat landscape outlining latest threats targeting mobile devices. More broadly speaking, they provide a high level overview of trend analysis and current threats that can impact a business's operating decisions.

# Collection

Since CTI teams ingest and disseminate information on a daily basis, it’s imperative that the final reports have adequate context so partner teams can take necessary action. A good place to start is by providing a threat assessment using [MITRE ATT&CK](https://attack.mitre.org/) to explain the attack chain complexity. Just don't play [MITRE ATT&CK Bingo](https://www.omeronsecurity.com/p/stop-playing-mitre-att-and-ck-bingo). The benefits of breaking down an attack chain help summarize threat reports into a detailed multi-step process showcasing how the actor or malware behaves. This can help teams answer questions like “Who are they targeting, what impact did this cause, are there any novel techniques being used?” There are many ways to convey this. Some companies provide a table of ATT&CK tactics and techniques in the footer, some inline, or even creating an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) SVG as a coverage heatmap. Last year, MITRE also released version 2 of [Attack Flow](https://github.com/center-for-threat-informed-defense/attack-flow) which can be used to create a detailed sequence of behaviors as a flow chart. If you're more of a visual person, you might tell the story through Navigator, Attack Flow or a timeline. This example below doesn't strictly use ATT&CK but a well-versed analyst can translate these procedural examples into relating tactics/techniques.

![Untitled](/cti/dfir.png)
> Timeline of IcedID's latest intrusion - TheDFIRReport

From here, teams receiving this intel have a better understanding of the attack and potential motive. Threat hunting teams now know how IcedID got in and build specific detections, network monitoring teams know the C2 IPs/domains and services used, the list goes on but the work doesn't stop there.
CTI primarily takes a reactive approach by sharing intel received from campaigns that have already happened. Data gathered from these campaigns should also be used in a proactive approach by enrichment indicators to visualize a relationship of how data may be related. This is where operational threat intelligence comes in. The goal of operational threat intelligence is to enhance visibility and context of raw data. I like to think this is a similar idea to Jared Atkinson's [Funnel of Fidelity](https://posts.specterops.io/introducing-the-funnel-of-fidelity-b1bb59b04036) model for detection and response.

![Untitled](/cti/funnel.png)

Including an IoC list in the report may not be sufficient for everyone. When referencing the pyramid of pain, indicators like hashes, IP addresses and domain names are respectively trivial, easy and simple. Searching for those artifacts alone and blacklisting them won’t be enough since samples can vary constantly and infrastructure can be torn down and built up by the next day. In cases like Lockbit, servers can come and go in 30 minutes. Outright blocking IPs isn't recommended anyway as you may block legitimate sites that a third-party uses.

![Untitled](/cti/pyramid.jpg)
> Pyramid of Pain from AttackIQ

To further enrich raw intel involves looking for patterns. This is the (A)ction in CTI. Action can be split into two parts; automated and curated. Automated covers the surface level detail that can either be gathered through direct interaction with the suspicious server, using open internet scanners like Censys and Shodan, or even a basic WHOIS lookup to show commonalities like registrant data and ASNs. Netflow analysis can reveal who else the specific host in question talks to in a given time frame which may support a hypothesis if other clients are residential, mobile, or company owned. This could also uncover additional ransomware victims or figure out who an initial access broker talks to. Automating netflow is a great way to find new hosts in real time. Gathering and contextualizing this data can be done through API scripts and then either stored in a local database or sent to a TIP, SIEM or SOAR platform. Curated intel comes from further enriching your dataset to build knowledge around what’s observed. This is more-so an art that gives your data a story. As it's an example of curated intelligence, I’ll share a recent event I dealt with.

# Story Time

A while back, domains were being registered following a specific pattern with accompanied default subdomains provided by cPanel. These sites were no doubt cPanel login pages but I was asked to look further into the reasoning behind this activity and why cPanel may have been used. The first step in providing curated intel is knowing the technology you’re talking about. Having used Cpanel in the past made it easier to explain but it always helps to search for other cases of abnormal domains hosted under a cPanel account. Looking at an investigation from Team Cymru, similar activity was observed with the same default subdomains being assigned to the malicious infrastructure. With that understanding, I could explain the reasoning behind each domain sharing the same subdomains.

Next step was to look into the individual domains. I usually start with IP resolution to uncover underlying infrastructure and pivotal data like public services and pDNS records. For phishing pages in general, URLScan is a great resource to uncover endpoints, malicious scripts or communication with IPs in various geographic regions. If this IP wasn’t related to a phishing page, a service like Greynoise could be useful to determine if it’s a port/vulnerability scanner, a Tor exit node, if it’s assigned to an ISP or mobile device, etc. A very useful service but for a different use case. Since I have visibility into current open ports, the next step is to explore and uncover details around the infrastructure other than knowing it’s associated with cPanel. A cursory look into the SMTP service of one IP revealed an SPF record pointing to another IP in a different network range but also a cPanel host.

>Two commands to inspect a specific domain's TXT record
> - `dig <domain> TXT`
> - `nslookup -q=TXT <domain>`

This quick check revealed an additional host that is allowed to send all emails to the original host. Doing the same check for the other IPs had different results like including domains related to cloud storage sites which you could hypothesize is an exfil location. Another site I use often is Hurricane Electric BGP Toolkit for a quick view of DNS info. A specific domain I queried showed it had two A records pointing to two different IPs. Latest pDNS data resolved both IPs to an AWS global accelerator and querying the next domain showed it shares the same. So now underlying infrastructure behind two domains reveals that they’re entry points into AWS application endpoints. The last domain I checked resolved to an IP that had a history of being used in a cyber espionage campaign in mid 2023 that distributed remote access trojans through Android messaging apps. That campaign is unrelated to how the IP is used now but it showcases it has a notorious background to begin with.

The conclusion of this investigation was that threat actors will use compromised cPanel accounts to assign their own malicious domains since the IP can resolve hundreds of other benign websites (the AWS Global Accelerator). It’s cheaper than running their own servers and they’re able to blend in with legitimate traffic. The intel gathered from this investigation revealed phishing behavior, additional communicating hosts, capabilities threat actors employ such as compromising legitimate cPanel accounts, and victimology from other sites masquerading as legitimate companies and products. As for the adversary, that part is still a bit grey given phishing scams aren’t easily attributable, but by querying VirusTotal for some of the IPs, communicating files can show what kind of malware is being spread. File hashes could be analyzed further to build YARA rules and provide continuous monitoring or alerts built in URLScan to maintain observability in domain patterns. In the event future intelligence shows the malware has changed like content within the HTML body, these rules can be updated.

# Conclusion

Enriching data provides a greater understanding of the threat which enhances the level of action that can be taken. As you include more teams in these conversations, that can further fine tune what kind of data you collect and determine what is of value or what could be improved. I'll close with a quote from BushidoToken's recent [post](https://blog.bushidotoken.net/2024/04/strengthening-proactive-cti-through.html):
> By establishing trust, providing contextualized insights, and facilitating executive awareness, CTI can effectively navigate executive inquiries and strengthen the organization's security posture in an ever-evolving threat landscape.

# References

- <https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion>
- <https://www.team-cymru.com/post/an-analysis-of-infrastructure-linked-to-the-hagga-threat-actor>
- <https://mitre-attack.github.io/attack-navigator/>
- <https://www.omeronsecurity.com/p/stop-playing-mitre-att-and-ck-bingo>
- <https://www.team-cymru.com/netflow>
- <https://blog.bushidotoken.net/2024/04/strengthening-proactive-cti-through.html>
