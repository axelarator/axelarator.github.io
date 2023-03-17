---
title: "BLE / NFC Threat Model"
date: 2023-03-17T11:22:25-06:00
draft: false
---

# Bluetooth Low Energy

Bluetooth Low Energy (BLE) is a wireless communication technology specially designed to prolong battery life of devices with different power consumption and usage capabilities. BLE started in Bluetooth version 4.2 with the latest being 5.x. It’s known as “Bluetooth Smart” whereas previous versions are referred to as “Bluetooth Classic”. Bluetooth operates at 2.4GHz with a max distance of 100 meters. Version 5 is backwards compatible and provides double the speed, four times the distance, lower power requirement, better security, and higher reliability.

![Untitled](/blenfc/Untitled.png)

## Protocol Stack

Within the **physical** layer, version 4.2 operates at 1Mbps and version 5.0 operates at 2Mbps.

The **link** layer is responsible for advertising, scanning, and creating/maintaining connections.

There are six states within the link layer:

* Standby
  * No transmission or reception of packets.
* Advertising
  * The link layer starts advertising packets and listens for responses.
* Scanning
  * In this state, the link layer listens for advertising packets from other advertising devices.
* Initiating
  * The link layer responds to advertising packets to initiate a connection.
* Connection
  * This comes after the initializing or advertising state. When coming from the former, it enters a master role. When coming from the latter, it enters a slave role.
* Synchronization
  * This state can be entered from the standby state. The link layer listens for periodic channel packets from specific devices advertising.

**HCI** uses standard interface types like UART/SPI/USB or by using an API to communicate between the controller and host.

**L2CAP** encapsulates data to upper layers.

**SMP** provides methods for device pairing and key distribution.

The **application** layer uses Bluetooth profiles to interact with applications. The profile defines the vertical interactions between the layers and P2P interactions of specific layers between devices.

The other layers within the host are explained below in more detail as they are the prime components of BLE connectivity.

**GAP**

The Generic Access Profile (GAP) controls connections and advertising in Bluetooth. It’s what determines how two devices can or cannot interact with each other.

Two roles exist within GAP:

* Peripheral
  * These are small, low power devices that connect to a more powerful central device. Peripheral devices can be heart rate monitors, a proximity tag, etc.
* Central
  * Central devices are usually the mobile phone or tablet that peripheral devices connect to.

For Bluetooth devices to announce themselves, two payloads exist within GAP.

* Advertising Data payload
  * This payload is mandatory. It contains up to 31 bytes of data and constantly transmits out from the device to let central devices in range know that it exists.
* Scan Response payload
  * Although optional, central devices can request a scan response payload. This allows device designers to fit more information in the advertising payload like strings for a device name.

So, when a peripheral wants to announce itself for a central device to connect to it, an advertising interval is set and every time the interval passes, it retransmits its main advertising packet. The listening device can request the scan response payload which tells the advertising payload to send additional data.

**GATT**

The Generic ATTribute Profile defines the way two BLE devices transfer data back and forth using Services and Characteristics. The Attribute Protocol (**ATT**) stores the services, characteristics and related data in a lookup table using 16-bit IDs for each entry.

* Services
  * Services contain chunks of data called characteristics. Each service is distinguished by a UUID in either 16-bit for BLE or 128-bit for custom services.
  * For example, the Heart Rate Service has a 16-bit UUID of 0x180D and contains up to three characteristics. Heart rate measurement, body sensor location, and heart rate control point.
* Characteristics
  * Like services, characteristics distinguish themselves by a 16-bit or 128-bit UUID.
  * Characteristics encapsulate a single data point (like the heart rate measurement).

GATT transactions operate through a server/client relationship. The peripheral is the GATT server which holds the ATT lookup data and service/characteristic definitions. The GATT client is the central device (phone/tablet) that sends requests to the server.

## Broadcasting

Sometimes, peripheral devices will only need to advertise data without requesting a scan response from a central device. The main reason may be that a peripheral device needs to send data to multiple devices at once. Broadcasting uses a custom payload in the advertising packet using the **Manufacturer Specific Data** field and sends it to central devices. After the connection is established, the BLE peripheral will stop sending packets and move to GATT services to communicate in both directions.

One peripheral device → One central device

One central device → Multiple peripherals

## Association Methods

Latest versions of BLE (4.2 and 5.x) introduced four association methods:

* Just Works
  * Uses a plain Elliptic-curve Diffie-Hellman key exchange without authentication of exchanged public keys.
* Out of Band
  * This requires a non-Bluetooth channel such as NFC for key exchanging. If the OOB channel is secure, passive eavesdropping and MITM attacks are mitigated. Due to requiring a non-Bluetooth channel, it is rarely used.
* Passkey Entry
  * Prompts the user to input a passkey. Then, the central device generates an Mconfirm and the peripheral generates an Sconfirm. Once the values are checked and matched, the link is encrypted using STK.
* Numeric Comparison
  * A user is given a 6-digit confirmation value and either states they match or not. A simple yes or no prompt without requiring the user to enter a code.

# NFC

NFC is a short-range low data rate wireless communication technology that operates at 13.56 MHz. These are known as high frequency tags since they are used with more complex readers to provide a cryptographic two-way data transfer. Low frequency RFID tags operate at 125 kHz and are used in systems that don’t require high security. These tags are used for things like parking deck entrances due to their longer range. The downside to low frequency tags is the low data transfer rate which hinders the use of complex two-way data transfer. They also only transmit a short ID without a means of authentication. Unlike Bluetooth, NFC is a contactless mode of communication that uses electromagnetic waves, and its distance is less than 10 cm.

The NFC network consists of an initiator device and target device. They can operate in either active-active or active-passive modes, but the NFC reader will always operate in active mode. Passive devices derive their power from received electromagnetic waves of the active device. An example of active-active mode is tapping your phone on the card reader at a store. An example of passive-active mode is using your work badge to enter a building. The badge does not have power until it is within range of the reader.

## Protocol Stack

The **application** layer formats the data to be exchanged between NFC devices using the NFC Data Exchange Format (NDEF).

The **data link** layer takes care of different modes of operation and anti-collision mechanisms.

The **physical** layer takes care of modulation, coding and RF related parameters like frequency and power.

## NFC Tags

These tags can be used within applications where small amounts of data can be stored and transferred to NFC devices.

Three modes exist in which NFC tag and readers work:

* Card Emulation
  * An NFC tag is read by an NFC compliant active reader.
  * The reader sends commands to the tag using an RF field.
  * The card responds to the reader as requested.
* Reader/Writer
  * One device is in read mode while the other is in write mode. This is used during product authentication, smart advertising, or device pairing.
  * The NFC reader reads NFC tags that are either passive or active.
  * In write mode, one NFC device writes to another.
* Point to Point
  * Any device can become the initiator and the other device(s) will act as the target to complete the connection.
  * This mode requires active devices on both ends.
  * The initiator sends commands by modulating the RF field and switches it off.
  * The target responds to the initiator using its own RF field modulation.

There are four types of tags to ensure interoperability between tag providers and NFC device manufacturers.

* Type 1
  * Cost effective and ideal for many NFC applications.
  * Based on ISO-14443A standard.
  * Read/write capable and users can configure the tag to be read-only.
  * 96 bytes of memory expandable up to 2KB.
  * No data collision protection.
* Type 2
  * Like type 1 tags but with collision support.
  * Based on ISO-14443A standard.
* Type 3
  * Derived from the non-secure parts of Sony FeliCa tags.
  * Costlier than type 1 and 2 tags.
  * Based on the Japanese Industrial Standard X 6319-4.
  * Pre-configured at the manufacturer to either be read/write or read-only.
  * Variable memory up to 1MB per service.
  * Anti-collision support.
* Type 4
  * Based on ISO-14443A standard.
  * Pre-configured at the manufacturer to either be read/write or read-only.
  * Variable memory up to 32KB per service.
  * Anti-collision support.
  * Supports three different speeds of 106, 212, or 424 Kbits/s.

## NFC Forum Standards

* NDEF
  * NFC Data Exchange Format ensures interoperability when transferring data to and from tags and between NFC devices. NDEF is exchanged in messages which consist of a sequence of records, with each record carrying a payload. The payload can include URLs, MIME media, or NFC-specific data types.
* RTD
  * Each NFC record type is specified in a Record Type Definition document.
    * NFC Text RTD
    * NFC URI RTD
    * NFC Smart Poster RTD
    * NFC Generic Control RTD
    * NFC Signature RTD
* LLCP
  * The Logical Link Control Protocol is a link layer protocol to enhance P2P mode of operation.
  * It introduces a two-way link-level connection.
  * Connection-oriented transfer acknowledges data exchange
  * Connectionless transfer is use for data exchanges that are unacknowledged.

# Attack Vector Examples

### Automotive

**Bluetooth**

An attacker could use a Bluetooth connection to:

* Execute code on the infotainment unit.
* Exploit a flaw in the Bluetooth stack of the infotainment unit.
* Upload malformed information, such as a corrupted address book designed to execute code.
* Access the vehicle from close ranges (less than 300 feet).
* Jam the Bluetooth device.

A specific use case is using Bluetooth enabled ODB device to sniff CAN bus traffic and intercept packets. An Arduino-based ODB-II Bluetooth adapter kit contains a data logger, GPS, accelerometer, and gyro and temperature sensors.

The CrossChasm C5 data logger can convert proprietary CAN packets into a generic format to send over Bluetooth.

* CAN is a simple protocol used in manufacturing and in the automobile industry. Your ECU communicates using the CAN protocol.

**Bluez (Bluetooth daemon)**

Older or unpatched versions of the Bluez daemon:

* May be exploitable.
* May be unable to handle corrupt address books.
* May not be configured to ensure proper encryption.
* May not be configured to handle secure handshaking.
* May use default passkeys.

### BlueSmacking

BlueSmacking is a way to execute DoS attacks against Bluetooth enabled devices. It uses the L2CAP layer of Bluetooth’s network stack to send oversized data packets.

### BlueJacking

BlueJacking is when one Bluetooth device hijacks another with spam advertising. This could include links to malicious sites or phishing campaigns to steal user data.

### BlueSnarfing

Like BlueJacking, BlueSnarfing can send data but also take it. Attackers can obtain texts, emails, photos, and the UUID of the victim device.

### BlueBugging

BlueBugging is an exploit that uses Bluetooth to establish a backdoor on a victim’s device.

### BLE Relay

Between versions 4.0 and 5.3, BLE was found to be vulnerable to relay attacks by forwarding GATT requests and responses. A new tool by NCC Group was developed to conduct a relay attack at the link layer level and is capable of relaying encrypted link layer communications. The added latency stays within the range of normal GATT response timing variations, bypassing current mitigations some products have in place. The latency introduced is as little as 8ms round-trip beyond normal operations. BLE devices have variable response times which is why the added 8ms stays within desired range. Given this attack can detect encrypted changes to connection parameters like intervals, WinOffset, PHY mode (physical layer), and channel map, it doesn’t matter if the link layer is encrypted or not.

### Downgrade Attack

BLE added a new Secure Connections Only (SCO) mode to address vulnerabilities found in previous versions of Bluetooth. The flaw is that the SCO mode only specifies that a BLE device needs to authenticate the mobile device, but the mobile device is not required to authenticate to the BLE device. So, an attacker can spoof a victim BLE device’s MAC address to create a fake BLE device and attack the initiator. A blocker launches a DoS attack and blocks a victim BLE device from connecting to a victim mobile device so that the fake device can connect instead. Sometimes a victim device only allows one connection. When one device connects, others are blocked out. To maintain hierarchy, the fake BLE deice can increase its advertising frequency so that it connects first.

### NFC Eavesdropping

An attacker uses an antenna to record communication between NFC devices. The attacker still needs to be in range, but if the channel is unencrypted, it makes it easy to corrupt information between the data exchange.

### NFC Data Modification

Data exchanged is captured and modified by an attacker’s RFID device using a jammer.

### NFC Relay Attack

By exploiting the ISO-14333 protocol, the attacker forwards the request of the reader to the victim and relays the answer back to the attacker device. The data is relayed over another communication channel (Bluetooth / WiFi) to a second NFC reader placed in proximity to the legit reader.

In the case of a Google Wallet relay attack, a relay reader (Mole) and card emulator (Proxy) were placed in between the smartcard and smartcard reader. Every command that the card emulator receives from the actual reader is forwarded to the mole that then forwards the command to the victim card. The card’s response is sent back by the mole to the actual reader through the proxy.

# Vulnerabilities

### BleedingTooth

BleedingTooth is a set of zero-click vulnerabilities in the Linux Bluetooth subsystem that can allow an unauthenticated remote attacker in short distance to execute arbitrary code with kernel privileges on vulnerable devices. Higher level protocols such as A2MP or SMP are built on top of L2CAP. These protocols are exposed without authentication and live inside the kernel.

* BadVibes (CVE-2020-24490) is a heap-based buffer overflow that affects devices with Bluetooth version 5.
* BadChoice (CVE-2020-12352) is a stack-based information leak that allows an attacker to leak memory addresses of the victim.
* BadKarma (CVE-2020-12351) is a heap-based type confusion.

BadChoice can be chained with BadVibes and BadKarma to achieve RCE. BadKarma is the only vulnerability not limited to Bluetooth 5.

A proof of concept is available here:

[https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth](https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth)

### BleedingBit

BleedingBit consists of two vulnerabilities affecting chips made by Texas Instruments. These chips are embedded in access points that deliver WiFi to enterprise networks. Successful exploitation allows unauthenticated attackers to break into enterprise networks undetected.

* CVE-2018-16986 is an RCE vulnerability triggered by an attacker sending advertising packets that contain malicious code stored on the memory of the BLE chip. An overflow packet is sent that allocates additional space, allowing the attacker to modify function pointers to point to their malicious code.
* CVE-2018-7080 is an over the air firmware download RCE vulnerability allowing attackers to rewrite the operating system on the BLE chip. The OAD feature does not address secure firmware updates, so a simple update mechanism is sent over a GATT transaction.

### SweynTooth

SweynTooth is a vulnerability family consisting of 12 vulnerabilities. They expose flaws in BLE SoC implementations that allow attackers in radio range to trigger deadlocks, crashes, buffer overflows, or bypass security.

A PoC is available here: [https://asset-group.github.io/disclosures/sweyntooth/](https://asset-group.github.io/disclosures/sweyntooth/)

| Vulnerability Type | Exploitable Remotely | Impact |
| ------------------ | -------------------- | ------ |
| Crash from Link Layer Length Overflow CVE-2019-16336 | No | An attacker can crash the device by triggering hard faults. If crash occurs, device may restart. The capability to restart depends on correct hard-fault handling mechanisms being implemented in the product using devices with the vulnerable BLE System on Chip (SoC). |
| Crash from Link Layer Length Overflow CVE-2019-17519 | No | An attacker can crash the device by triggering hard faults. This could initially result in a denial-of-service condition. |
| Crash from Truncated L2CAP CVE-2019-17517 | No | An attacker in radio range can use this attack to cause a denial-of-service condition and crash the device. |
| Crash from Silent Length Overflow CVE-2019-17518 | No | An attacker in radio range can use this attack to cause a denial-of-service condition and crash the device.
| Unexpected Public Key Crash CVE-2019-17520 | No | An attacker in radio range can exploit this vulnerability to cause a denial-of-service condition. The product may not properly handle hard faults and enter a deadlock state. This may require a manual restart. |
| Crash from Invalid L2CAP Fragment CVE-2019-19195 | No | An attacker can crash the device by triggering hard faults. If crash occurs, device may restart. The capability to restart depends on correct hard-fault handling mechanisms being implemented in the product using the vulnerable BLE SoC. |
| Crash from Key Size Overflow CVE-2019-19196 | No | This vulnerability allows an attacker in radio range to perform buffer overflow and crash products with pairing support enabled, which is common practice in several BLE products. In the worst case, it could be possible to overwrite buffers that store encryption nonce, which could allow the attacker to bypass encryption and leak user information.
| Link Layer LLID deadlock CVE-2019-17061 | No | The availability of the BLE connection can be affected without causing a hard fault or memory corruption and can result in deadlock. Crashes originating from hard faults, if not properly handled, can become a deadlock if the device is not automatically restarted. In most cases, when a deadlock occurs, the user is required to manually power off and power on the device to re-establish proper BLE communication. |
| Link Layer LLID deadlock CVE-2019-17060 | No | The availability of BLE products could be critically impaired, likely requiring the user to manually perform a power cycle on the product to re-establish BLE communication. |
| Sequential ATT Deadlock CVE-2019-19192 | No | This vulnerability can leave the product in a deadlock state and would require a restart either manually or by mechanisms built into the firmware. |
| Deadlock from Invalid Connection Request CVE-2019-19193 | No | An attacker in radio range can cause a denial-of-service condition in the affected products using the vulnerable SoCs. Crashes originating from hard faults, if not properly handled, can become a deadlock if the device is not automatically restarted. In most cases, when a deadlock occurs, the user is required to manually power off and power on the device to re-establish proper BLE communication. |
| Security bypass from Zero LTK Installation CVE-2019-19194 | No | Allows attackers in radio range to bypass the latest secure pairing mode of BLE, i.e., the Secure Connections pairing mode. An attacker in radio range may have arbitrary read or write access to the device’s functions. |

# Tools

* [RFIDIot](https://github.com/AdamLaurie/RFIDIOt) is a collection of tools and libraries for exploring RFID technology.
* [pn532mitm.py](https://github.com/AdamLaurie/RFIDIOt/blob/master/pn532mitm.py) is a script within RFIDIot to create a MiTM attack.
* [hcitool](https://linux.die.net/man/1/hcitool) makes use of the host controller interface in a laptop to communicate and read/write changes to BLE devices.
  * In order to change data, the attacker needs to know the service and characteristic the data is coming from. To find that, use gatttool.
* [gatttool](https://manpages.ubuntu.com/manpages/bionic/man1/gatttool.1.html) is used for finding out the services and characteristics of an available BLE device.
* [Bettercap](https://github.com/bettercap/bettercap) is a framework to perform attacks against WiFi networks, BLE devices, wireless HID devices and ethernet networks.
* Flipper Zero is a multipurpose tool with the ability to interact with both low frequency (125 kHz) and high frequency (13.56 MHz) tags.

# References

* [Intro to BLE](https://learn.adafruit.com/introduction-to-bluetooth-low-energy/introduction)
* [BlueTooth Tutorial](https://www.rfwireless-world.com/Tutorials/Bluetooth_tutorial.html)
* [NFC Tutorial](https://www.rfwireless-world.com/Tutorials/NFC-Near-Field-Communication-tutorial.html)
* [BLE profiles and services](https://www.bluetooth.com/specifications/specs/)
* [BLE characteristics](https://www.bluetooth.com/specifications/assigned-numbers/)
* [BLE Relay Attack](https://research.nccgroup.com/2022/05/15/technical-advisory-ble-proximity-authentication-vulnerable-to-relay-attacks/)
* [BLE Downgrade Attacks](https://www.usenix.org/system/files/sec20-zhang-yue.pdf)
* [NFC Vulnerabilities](https://resources.infosecinstitute.com/topic/near-field-communication-nfc-technology-vulnerabilities-and-principal-attack-schema/)
* [Guide to BLE Hacking](https://blog.attify.com/the-practical-guide-to-hacking-bluetooth-low-energy/)
* [Sweyntooth](https://asset-group.github.io/disclosures/sweyntooth/)
* [Bleedingbit](https://www.armis.com/research/bleedingbit/)
* [BleedingTooth](https://google.github.io/security-research/pocs/linux/bleedingtooth/writeup.html#badvibes-heap-based-buffer-overflow-cve-2020-24490)
