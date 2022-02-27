# Snort

Source code to interact with installed version of Snort container/OS through subprocesses

# Parsing
Snort python module will parse output to console
Example output from Python Subprocess call to Snort

```
       --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/etc/snort.conf"
PortVar 'HTTP_PORTS' defined :  [ 36 80:90 311 383 555 591 593 631 801 808 818 901 972 1158 1220 1414 1533 1741 1830 1942 2231 2301 2381 2578 2809 2980 3029 3037 3057 3128 3443 3702 4000 4343 4848 5000 5117 5250 5600 6080 6173 6988 7000:7001 7071 7144:7145 7510 7770 7777:7779 8000 8008 8014 8028 8080:8082 8085 8088 8090 8118 8123 8180:8181 8222 8243 8280 8300 8333 8344 8500 8509 8800 8888 8899 8983 9000 9060 9080 9090:9091 9111 9290 9443 9999:10000 11371 12601 13014 15489 29991 33300 34412 34443:34444 41080 44449 50000 50002 51423 53331 55252 55555 56712 ]
PortVar 'SHELLCODE_PORTS' defined :  [ 0:79 81:65535 ]
PortVar 'ORACLE_PORTS' defined :  [ 1024:65535 ]
PortVar 'SSH_PORTS' defined :  [ 22 ]
PortVar 'FTP_PORTS' defined :  [ 21 2100 3535 ]
PortVar 'SIP_PORTS' defined :  [ 5060:5061 5600 ]
PortVar 'FILE_DATA_PORTS' defined :  [ 36 80:90 110 143 311 383 555 591 593 631 801 808 818 901 972 1158 1220 1414 1533 1741 1830 1942 2231 2301 2381 2578 2809 2980 3029 3037 3057 3128 3443 3702 4000 4343 4848 5000 5117 5250 5600 6080 6173 6988 7000:7001 7071 7144:7145 7510 7770 7777:7779 8000 8008 8014 8028 8080:8082 8085 8088 8090 8118 8123 8180:8181 8222 8243 8280 8300 8333 8344 8500 8509 8800 8888 8899 8983 9000 9060 9080 9090:9091 9111 9290 9443 9999:10000 11371 12601 13014 15489 29991 33300 34412 34443:34444 41080 44449 50000 50002 51423 53331 55252 55555 56712 ]
PortVar 'GTP_PORTS' defined :  [ 2123 2152 3386 ]
Detection:
   Search-Method = AC-Full-Q
    Split Any/Any group = enabled
    Search-Method-Optimizations = enabled
    Maximum pattern length = 20
Found profile_rules config directive (print all, sort total_ticks, filename rules_stats.txt)
Tagged Packet Limit: 256
Loading dynamic engine /usr/local/lib/snort_dynamicengine/libsf_engine.so... done
Loading all dynamic detection libs from /usr/local/lib/snort_dynamicrules...
WARNING: No dynamic libraries found in directory /usr/local/lib/snort_dynamicrules.
  Finished Loading all dynamic detection libs from /usr/local/lib/snort_dynamicrules
Loading all dynamic preprocessor libs from /usr/local/lib/snort_dynamicpreprocessor/...
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_s7commplus_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_sip_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_modbus_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_gtp_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_dns_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_dce2_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_ssh_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_appid_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_pop_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_imap_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_ftptelnet_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_reputation_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_smtp_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_dnp3_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_ssl_preproc.so... done
  Loading dynamic preprocessor library /usr/local/lib/snort_dynamicpreprocessor//libsf_sdf_preproc.so... done
  Finished Loading all dynamic preprocessor libs from /usr/local/lib/snort_dynamicpreprocessor/
Log directory = /var/log/snort
WARNING: ip4 normalizations disabled because not inline.
WARNING: tcp normalizations disabled because not inline.
WARNING: icmp4 normalizations disabled because not inline.
WARNING: ip6 normalizations disabled because not inline.
WARNING: icmp6 normalizations disabled because not inline.
Frag3 global config:
    Max frags: 65536
    Fragment memory cap: 4194304 bytes
Frag3 engine config:
    Bound Address: default
    Target-based policy: WINDOWS
    Fragment timeout: 180 seconds
    Fragment min_ttl:   1
    Fragment Anomalies: Alert
    Overlap Limit:     10
    Min fragment Length:     100
      Max Expected Streams: 768
Stream global config:
    Track TCP sessions: ACTIVE
    Max TCP sessions: 262144
    TCP cache pruning timeout: 30 seconds
    TCP cache nominal timeout: 3600 seconds
    Memcap (for reassembly packet storage): 8388608
    Track UDP sessions: ACTIVE
    Max UDP sessions: 131072
    UDP cache pruning timeout: 30 seconds
    UDP cache nominal timeout: 180 seconds
    Track ICMP sessions: INACTIVE
    Track IP sessions: INACTIVE
    Log info if session memory consumption exceeds 1048576
    Send up to 2 active responses
    Wait at least 5 seconds between responses
    Protocol Aware Flushing: ACTIVE
        Maximum Flush Point: 16000
Stream TCP Policy config:
    Bound Address: default
    Reassembly Policy: WINDOWS
    Timeout: 180 seconds
    Limit on TCP Overlaps: 10
    Maximum number of bytes to queue per session: 1048576
    Maximum number of segs to queue per session: 2621
    Options:
        Require 3-Way Handshake: YES
        3-Way Handshake Timeout: 180
        Detect Anomalies: YES
    Reassembly Ports:
      21 client (Footprint) 
      22 client (Footprint) 
      23 client (Footprint) 
      25 client (Footprint) 
      36 client (Footprint) server (Footprint)
      42 client (Footprint) 
      53 client (Footprint) 
      70 client (Footprint) 
      79 client (Footprint) 
      80 client (Footprint) server (Footprint)
      81 client (Footprint) server (Footprint)
      82 client (Footprint) server (Footprint)
      83 client (Footprint) server (Footprint)
      84 client (Footprint) server (Footprint)
      85 client (Footprint) server (Footprint)
      86 client (Footprint) server (Footprint)
      87 client (Footprint) server (Footprint)
      88 client (Footprint) server (Footprint)
      89 client (Footprint) server (Footprint)
      90 client (Footprint) server (Footprint)
      additional ports configured but not printed.
Stream UDP Policy config:
    Timeout: 180 seconds
HttpInspect Config:
    GLOBAL CONFIG
      Detect Proxy Usage:       NO
      IIS Unicode Map Filename: /etc/snort/etc/unicode.map
      IIS Unicode Map Codepage: 1252
      Memcap used for logging URI and Hostname: 150994944
      Max Gzip Memory: 838860
      Max Gzip Sessions: 1807
      Gzip Compress Depth: 65535
      Gzip Decompress Depth: 65535
      Normalize Random Nulls in Text: NO
    DEFAULT SERVER CONFIG:
      Server profile: All
      Ports (PAF): 36 80 81 82 83 84 85 86 87 88 89 90 311 383 555 591 593 631 801 808 818 901 972 1158 1220 1414 1533 1741 1830 1942 2231 2301 2381 2578 2809 2980 3029 3037 3057 3128 3443 3702 4000 4343 4848 5000 5117 5250 5600 6080 6173 6988 7000 7001 7071 7144 7145 7510 7770 7777 7778 7779 8000 8008 8014 8028 8080 8081 8082 8085 8088 8090 8118 8123 8180 8181 8222 8243 8280 8300 8333 8344 8500 8509 8800 8888 8899 8983 9000 9060 9080 9090 9091 9111 9290 9443 9999 10000 11371 12601 13014 15489 29991 33300 34412 34443 34444 41080 44449 50000 50002 51423 53331 55252 55555 56712 
      Server Flow Depth: 0
      Client Flow Depth: 0
      Max Chunk Length: 500000
      Small Chunk Length Evasion: chunk size <= 10, threshold >= 5 times
      Max Header Field Length: 750
      Max Number Header Fields: 100
      Max Number of WhiteSpaces allowed with header folding: 200
      Inspect Pipeline Requests: YES
      URI Discovery Strict Mode: NO
      Allow Proxy Usage: NO
      Disable Alerting: NO
      Oversize Dir Length: 500
      Only inspect URI: NO
      Normalize HTTP Headers: NO
      Inspect HTTP Cookies: YES
      Inspect HTTP Responses: YES
      Extract Gzip from responses: YES
      Decompress response files:   
      Unlimited decompression of gzip data from responses: YES
      Normalize Javascripts in HTTP Responses: YES
      Max Number of WhiteSpaces allowed with Javascript Obfuscation in HTTP responses: 200
      Normalize HTTP Cookies: NO
      Enable XFF and True Client IP: NO
      Log HTTP URI data: NO
      Log HTTP Hostname data: NO
      Extended ASCII code support in URI: NO
      Ascii: YES alert: NO
      Double Decoding: YES alert: NO
      %U Encoding: YES alert: YES
      Bare Byte: YES alert: NO
      UTF 8: YES alert: NO
      IIS Unicode: YES alert: NO
      Multiple Slash: YES alert: NO
      IIS Backslash: YES alert: NO
      Directory Traversal: YES alert: NO
      Web Root Traversal: YES alert: NO
      Apache WhiteSpace: YES alert: NO
      IIS Delimiter: YES alert: NO
      IIS Unicode Map: GLOBAL IIS UNICODE MAP CONFIG
      Non-RFC Compliant Characters: 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 
      Whitespace Characters: 0x09 0x0b 0x0c 0x0d 
      Legacy mode: NO
rpc_decode arguments:
    Ports to decode RPC on: 111 32770 32771 32772 32773 32774 32775 32776 32777 32778 32779 
    alert_fragments: INACTIVE
    alert_large_fragments: INACTIVE
    alert_incomplete: INACTIVE
    alert_multiple_requests: INACTIVE
FTPTelnet Config:
    GLOBAL CONFIG
      Inspection Type: stateful
      Check for Encrypted Traffic: YES alert: NO
      Continue to check encrypted data: YES
    TELNET CONFIG:
      Ports: 23 
      Are You There Threshold: 20
      Normalize: YES
      Detect Anomalies: YES
    FTP CONFIG:
      FTP Server: default
        Ports (PAF): 21 2100 3535 
        Check for Telnet Cmds: YES alert: YES
        Ignore Telnet Cmd Operations: YES alert: YES
        Ignore open data channels: NO
      FTP Client: default
        Check for Bounce Attacks: YES alert: YES
        Check for Telnet Cmds: YES alert: YES
        Ignore Telnet Cmd Operations: YES alert: YES
        Max Response Length: 256
SMTP Config:
    Ports: 25 465 587 691 
    Inspection Type: Stateful
    Normalize: ATRN AUTH BDAT DATA DEBUG EHLO EMAL ESAM ESND ESOM ETRN EVFY EXPN HELO HELP IDENT MAIL NOOP ONEX QUEU QUIT RCPT RSET SAML SEND STARTTLS SOML TICK TIME TURN TURNME VERB VRFY X-EXPS XADR XAUTH XCIR XEXCH50 XGEN XLICENSE X-LINK2STATE XQUE XSTA XTRN XUSR CHUNKING X-ADAT X-DRCP X-ERCP X-EXCH50 
    Ignore Data: No
    Ignore TLS Data: No
    Ignore SMTP Alerts: No
    Max Command Line Length: 512
    Max auth Command Line Length: 1000
    Max Specific Command Line Length: 
       ATRN:255 AUTH:246 BDAT:255 DATA:246 DEBUG:255 
       EHLO:500 EMAL:255 ESAM:255 ESND:255 ESOM:255 
       ETRN:246 EVFY:255 EXPN:255 HELO:500 HELP:500 
       IDENT:255 MAIL:260 NOOP:255 ONEX:246 QUEU:246 
       QUIT:246 RCPT:300 RSET:246 SAML:246 SEND:246 
       SIZE:255 STARTTLS:246 SOML:246 TICK:246 TIME:246 
       TURN:246 TURNME:246 VERB:246 VRFY:255 X-EXPS:246 
       XADR:246 XAUTH:246 XCIR:246 XEXCH50:246 XGEN:246 
       XLICENSE:246 X-LINK2STATE:246 XQUE:246 XSTA:246 XTRN:246 
       XUSR:246 
    Max Header Line Length: 1000
    Max Response Line Length: 512
    X-Link2State Alert: Yes
    Drop on X-Link2State Alert: No
    Alert on commands: None
    Alert on unknown commands: No
    SMTP Memcap: 838860
    MIME Max Mem: 838860
    Base64 Decoding: Enabled
    Base64 Decoding Depth: Unlimited
    Quoted-Printable Decoding: Enabled
    Quoted-Printable Decoding Depth: Unlimited
    Unix-to-Unix Decoding: Enabled
    Unix-to-Unix Decoding Depth: Unlimited
    Non-Encoded MIME attachment Extraction: Enabled
    Non-Encoded MIME attachment Extraction Depth: Unlimited
    Log Attachment filename: Enabled
    Log MAIL FROM Address: Enabled
    Log RCPT TO Addresses: Enabled
    Log Email Headers: Enabled
    Email Hdrs Log Depth: 1464
SSH config: 
    Autodetection: ENABLED
    Challenge-Response Overflow Alert: ENABLED
    SSH1 CRC32 Alert: ENABLED
    Server Version String Overflow Alert: ENABLED
    Protocol Mismatch Alert: ENABLED
    Bad Message Direction Alert: DISABLED
    Bad Payload Size Alert: DISABLED
    Unrecognized Version Alert: DISABLED
    Max Encrypted Packets: 20  
    Max Server Version String Length: 100  
    MaxClientBytes: 19600 (Default) 
    Ports:
        22
DCE/RPC 2 Preprocessor Configuration
  Global Configuration
    DCE/RPC Defragmentation: Enabled
    Memcap: 102400 KB
    Events: co 
    SMB Fingerprint policy: Disabled
  Server Default Configuration
    Policy: WinXP
    Detect ports (PAF)
      SMB: 139 445 
      TCP: 135 
      UDP: 135 
      RPC over HTTP server: 593 
      RPC over HTTP proxy: None
    Autodetect ports (PAF)
      SMB: None
      TCP: 1025-65535 
      UDP: 1025-65535 
      RPC over HTTP server: 1025-65535 
      RPC over HTTP proxy: None
    Invalid SMB shares: C$ D$ ADMIN$ 
    Maximum SMB command chaining: 3 commands
    SMB file inspection: Disabled
DNS config: 
    DNS Client rdata txt Overflow Alert: ACTIVE
    Obsolete DNS RR Types Alert: INACTIVE
    Experimental DNS RR Types Alert: INACTIVE
    Ports: 53
SSLPP config:
    Encrypted packets: not inspected
    Ports:
      443      465      563      636      989
      992      993      994      995     5061
     7801     7802     7900     7901     7902
     7903     7904     7905     7906     7907
     7908     7909     7910     7911     7912
     7913     7914     7915     7916     7917
     7918     7919     7920
    Server side data is trusted
    Maximum SSL Heartbeat length: 0
Sensitive Data preprocessor config: 
    Global Alert Threshold: 25
    Masked Output: DISABLED
SIP config: 
    Max number of sessions: 40000  
    Max number of dialogs in a session: 4 (Default) 
    Status: ENABLED
    Ignore media channel: DISABLED
    Max URI length: 512  
    Max Call ID length: 80  
    Max Request name length: 20 (Default) 
    Max From length: 256 (Default) 
    Max To length: 256 (Default) 
    Max Via length: 1024 (Default) 
    Max Contact length: 512  
    Max Content length: 2048  
    Ports:
        5060    5061    5600
    Methods:
          invite cancel ack bye register options refer subscribe update join info message notify benotify do qauth sprack publish service unsubscribe prack
IMAP Config:
    Ports: 143 
    IMAP Memcap: 838860
    MIME Max Mem: 838860
    Base64 Decoding: Enabled
    Base64 Decoding Depth: Unlimited
    Quoted-Printable Decoding: Enabled
    Quoted-Printable Decoding Depth: Unlimited
    Unix-to-Unix Decoding: Enabled
    Unix-to-Unix Decoding Depth: Unlimited
    Non-Encoded MIME attachment Extraction: Enabled
    Non-Encoded MIME attachment Extraction Depth: Unlimited
POP Config:
    Ports: 110 
    POP Memcap: 838860
    MIME Max Mem: 838860
    Base64 Decoding: Enabled
    Base64 Decoding Depth: Unlimited
    Quoted-Printable Decoding: Enabled
    Quoted-Printable Decoding Depth: Unlimited
    Unix-to-Unix Decoding: Enabled
    Unix-to-Unix Decoding Depth: Unlimited
    Non-Encoded MIME attachment Extraction: Enabled
    Non-Encoded MIME attachment Extraction Depth: Unlimited
Modbus config: 
    Ports:
        502
DNP3 config: 
    Memcap: 262144
    Check Link-Layer CRCs: ENABLED
    Ports:
        20000
Reputation config: 
WARNING: Can't find any whitelist/blacklist entries. Reputation Preprocessor disabled.

+++++++++++++++++++++++++++++++++++++++++++++++++++
Initializing rule chains...
6 Snort rules read
    6 detection rules
    0 decoder rules
    0 preprocessor rules
6 Option Chains linked into 3 Chain Headers
+++++++++++++++++++++++++++++++++++++++++++++++++++

+-------------------[Rule Port Counts]---------------------------------------
|             tcp     udp    icmp      ip
|     src       4       0       0       0
|     dst       0       0       0       0
|     any       1       0       1       0
|      nc       1       0       1       0
|     s+d       0       0       0       0
+----------------------------------------------------------------------------

+-----------------------[detection-filter-config]------------------------------
| memory-cap : 1048576 bytes
+-----------------------[detection-filter-rules]-------------------------------
| none
-------------------------------------------------------------------------------

+-----------------------[rate-filter-config]-----------------------------------
| memory-cap : 1048576 bytes
+-----------------------[rate-filter-rules]------------------------------------
| none
-------------------------------------------------------------------------------

+-----------------------[event-filter-config]----------------------------------
| memory-cap : 1048576 bytes
+-----------------------[event-filter-global]----------------------------------
+-----------------------[event-filter-local]-----------------------------------
| none
+-----------------------[suppression]------------------------------------------
| none
-------------------------------------------------------------------------------
Rule application order: pass->drop->sdrop->reject->alert->log
Verifying Preprocessor Configurations!

[ Port Based Pattern Matching Memory ]
+- [ Aho-Corasick Summary ] -------------------------------------
| Storage Format    : Full-Q 
| Finite Automaton  : DFA
| Alphabet Size     : 256 Chars
| Sizeof State      : Variable (1,2,4 bytes)
| Instances         : 1
|     1 byte states : 1
|     2 byte states : 0
|     4 byte states : 0
| Characters        : 30
| States            : 27
| Transitions       : 52
| State Density     : 0.8%
| Patterns          : 4
| Match States      : 4
| Memory (KB)       : 17.12
|   Pattern         : 0.37
|   Match Lists     : 0.55
|   DFA
|     1 byte states : 7.01
|     2 byte states : 0.00
|     4 byte states : 0.00
+----------------------------------------------------------------
[ Number of patterns truncated to 20 bytes: 0 ]
pcap DAQ configured to read-file.
Acquiring network traffic from "icmp_8888.pcap".
Reload thread starting...
Reload thread started, thread 0x7f3d1513a700 (15)
WARNING: active responses disabled since DAQ can't inject packets.

        --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.18.1 GRE (Build 1005) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11

           Rules Engine: SF_SNORT_DETECTION_ENGINE  Version 3.2  <Build 1>
           Preprocessor Object: SF_SDF  Version 1.1  <Build 1>
           Preprocessor Object: SF_SSLPP  Version 1.1  <Build 4>
           Preprocessor Object: SF_DNP3  Version 1.1  <Build 1>
           Preprocessor Object: SF_SMTP  Version 1.1  <Build 9>
           Preprocessor Object: SF_REPUTATION  Version 1.1  <Build 1>
           Preprocessor Object: SF_FTPTELNET  Version 1.2  <Build 13>
           Preprocessor Object: SF_IMAP  Version 1.0  <Build 1>
           Preprocessor Object: SF_POP  Version 1.0  <Build 1>
           Preprocessor Object: appid  Version 1.1  <Build 5>
           Preprocessor Object: SF_SSH  Version 1.1  <Build 3>
           Preprocessor Object: SF_DCERPC2  Version 1.0  <Build 3>
           Preprocessor Object: SF_DNS  Version 1.1  <Build 4>
           Preprocessor Object: SF_GTP  Version 1.1  <Build 1>
           Preprocessor Object: SF_MODBUS  Version 1.1  <Build 1>
           Preprocessor Object: SF_SIP  Version 1.1  <Build 1>
           Preprocessor Object: SF_S7COMMPLUS  Version 1.0  <Build 1>
Commencing packet processing (pid=14)
02/26/22-21:02:33.357151  [**] [1:1000004:0] Pinging... [**] [Priority: 0] {ICMP} 192.168.52.129 -> 8.8.8.8
02/26/22-21:02:34.359349  [**] [1:1000004:0] Pinging... [**] [Priority: 0] {ICMP} 192.168.52.129 -> 8.8.8.8
02/26/22-21:02:35.361522  [**] [1:1000004:0] Pinging... [**] [Priority: 0] {ICMP} 192.168.52.129 -> 8.8.8.8
02/26/22-21:02:36.362643  [**] [1:1000004:0] Pinging... [**] [Priority: 0] {ICMP} 192.168.52.129 -> 8.8.8.8
===============================================================================
Run time for packet processing was 1.146 seconds
Snort processed 10 packets.
Snort ran for 0 days 0 hours 0 minutes 1 seconds
   Pkts/sec:           10
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       10731520
  Bytes in mapped regions (hblkhd):      29995008
  Total allocated space (uordblks):      5265632
  Total free space (fordblks):           5465888
  Topmost releasable block (keepcost):   121872
===============================================================================
Packet I/O Totals:
   Received:           10
   Analyzed:           10 (100.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            0 (  0.000%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:           10 (100.000%)
       VLAN:            0 (  0.000%)
        IP4:           10 (100.000%)
       Frag:            0 (  0.000%)
       ICMP:            8 ( 80.000%)
        UDP:            2 ( 20.000%)
        TCP:            0 (  0.000%)
        IP6:            0 (  0.000%)
    IP6 Ext:            0 (  0.000%)
   IP6 Opts:            0 (  0.000%)
      Frag6:            0 (  0.000%)
      ICMP6:            0 (  0.000%)
       UDP6:            0 (  0.000%)
       TCP6:            0 (  0.000%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
        GRE:            0 (  0.000%)
    GRE Eth:            0 (  0.000%)
   GRE VLAN:            0 (  0.000%)
    GRE IP4:            0 (  0.000%)
    GRE IP6:            0 (  0.000%)
GRE IP6 Ext:            0 (  0.000%)
   GRE PPTP:            0 (  0.000%)
    GRE ARP:            0 (  0.000%)
    GRE IPX:            0 (  0.000%)
   GRE Loop:            0 (  0.000%)
       MPLS:            0 (  0.000%)
        ARP:            0 (  0.000%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:            0 (  0.000%)
   IP6 Disc:            0 (  0.000%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:            0 (  0.000%)
      Other:            0 (  0.000%)
Bad Chk Sum:            1 ( 10.000%)
    Bad TTL:            0 (  0.000%)
     S5 G 1:            0 (  0.000%)
     S5 G 2:            0 (  0.000%)
      Total:           10
===============================================================================
Action Stats:
     Alerts:            4 ( 40.000%)
     Logged:            4 ( 40.000%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:           10 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Frag3 statistics:
        Total Fragments: 0
      Frags Reassembled: 0
               Discards: 0
          Memory Faults: 0
               Timeouts: 0
               Overlaps: 0
              Anomalies: 0
                 Alerts: 0
                  Drops: 0
     FragTrackers Added: 0
    FragTrackers Dumped: 0
FragTrackers Auto Freed: 0
    Frag Nodes Inserted: 0
     Frag Nodes Deleted: 0
===============================================================================
===============================================================================
Stream statistics:
            Total sessions: 1
              TCP sessions: 0
       Active TCP sessions: 0
  Non mempool TCP sess mem: 0
          TCP mempool used: 0
              UDP sessions: 1
       Active UDP sessions: 1
          UDP mempool used: 0
             ICMP sessions: 0
      Active ICMP sessions: 0
         ICMP mempool used: 0
               IP sessions: 0
        Active IP sessions: 0
           IP mempool used: 0
                TCP Prunes: 0
                UDP Prunes: 0
               ICMP Prunes: 0
                 IP Prunes: 0
TCP StreamTrackers Created: 0
TCP StreamTrackers Deleted: 0
              TCP Timeouts: 0
              TCP Overlaps: 0
       TCP Segments Queued: 0
     TCP Segments Released: 0
       TCP Rebuilt Packets: 0
         TCP Segments Used: 0
              TCP Discards: 0
                  TCP Gaps: 0
      UDP Sessions Created: 1
      UDP Sessions Deleted: 1
              UDP Timeouts: 0
              UDP Discards: 0
     ICMP Dest unreachable: 0
 ICMP Fragmentation needed: 0
                    Events: 0
           Internal Events: 0
           TCP Port Filter
                  Filtered: 0
                 Inspected: 0
                   Tracked: 0
           UDP Port Filter
                  Filtered: 0
                 Inspected: 0
                   Tracked: 1
===============================================================================
===============================================================================
FTPTelnet Preprocessor Statistics
  Current active FTP sessions                   : 0
  Max concurrent FTP sessions                   : 0
  Total FTP Data sessions                       : 0
  Max concurrent FTP Data sessions              : 0
  Current active Telnet sessions                : 0
  Max concurrent Telnet sessions                : 0
  Current ftp_telnet session non-mempool memory : 0
===============================================================================
SMTP Preprocessor Statistics
  Total sessions                                    : 0
  Max concurrent sessions                           : 0
===============================================================================
dcerpc2 Preprocessor Statistics
  Total sessions: 0
 Active sessions: 0

  Memory stats (bytes)
    Current total: 52428800
    Maximum total: 52515830
    Current runtime total: 52428800
    Maximum runtime total: 52428800
    Current config total: 0
    Maximum config total: 82508
    Current rule options total: 0
    Maximum rule options total: 0
    Current routing table total: 0
    Maximum routing table total: 0
    Current initialization total: 0
    Maximum initialization total: 4586
===============================================================================
===============================================================================
SIP Preprocessor Statistics
  Total sessions: 0
===============================================================================
IMAP Preprocessor Statistics
  Total sessions                                    : 0
  Max concurrent sessions                           : 0
===============================================================================
POP Preprocessor Statistics
  Total sessions                                    : 0
  Max concurrent sessions                           : 0
===============================================================================
Reputation Preprocessor Statistics
  Total Memory Allocated: 0
===============================================================================

Memory Statistics of DNS at: Mon Feb 28 00:26:59 2022


Heap Statistics of dns:
          Total Statistics:
               Memory in use:              0 bytes
                No of allocs:              1
                 No of frees:              1
         Config Statistics:
               Memory in use:              0 bytes
                No of allocs:              1
                 No of frees:              1
===============================================================================

Memory Statistics of Frag3 on: Mon Feb 28 00:26:59 2022

    Memory in use         : 0
    prealloc nodes in use : 0


Heap Statistics of frag:
          Total Statistics:
               Memory in use:              0 bytes
                No of allocs:              3
                 No of frees:              3
         Config Statistics:
               Memory in use:              0 bytes
                No of allocs:              3
                 No of frees:              3
===============================================================================

Memory Statistics of FTPTelnet at: Mon Feb 28 00:26:59 2022

       Current active FTP sessions :    0
       Max concurrent FTP sessions :    0
           Total FTP Data sessions :    0
  Max concurrent FTP Data sessions :    0
    Current active Telnet sessions :    0
    Max concurrent Telnet sessions :    0

Heap Statistics of ftptelnet:
          Total Statistics:
               Memory in use:              0 bytes
                No of allocs:            622
                 No of frees:            622
         Config Statistics:
               Memory in use:              0 bytes
                No of allocs:            622
                 No of frees:            622
===============================================================================
 Memory Statistics of Http Inspect on: Mon Feb 28 00:26:59 2022
     Current active session          : 0    No of POST methods encountered  : 0    No of GET methods encountered   : 0    No of successfully extract post params      : 0    No of successfully extract request params   : 0    No of successfully extract response params  : 0 Http Memory Pool       :      Free Memory:                 0 bytes       Used Memory:                 0 bytes       Max Memory :                 0 bytes  Mime Decode Memory Pool   :      Free Memory:                 0 bytes      Used Memory:                 0 bytes      Max Memory :                 0 bytes Http Gzip Memory Pool     :      Free Memory:                 0 bytes      Used Memory:                 0 bytes      Max Memory :                 0 bytes Http Mime log Memory Pool :      Free Memory:                 0 bytes      Used Memory:                 0 bytes      Max Memory :                 0 bytes
Heap Statistics of httpinspect:
          Total Statistics:
               Memory in use:              0 bytes
                No of allocs:              5
                 No of frees:              5
        Session Statistics:
               Memory in use:              0 bytes
                No of allocs:              1
                 No of frees:              1
         Config Statistics:
               Memory in use:              0 bytes
                No of allocs:              3
                 No of frees:              3
        Mempool Statistics:
               Memory in use:              0 bytes
                No of allocs:              1
                 No of frees:              1
===============================================================================
SMTP Preprocessor Statistics
  Total sessions                : 0 
  Max concurrent sessions       : 0 
  Current sessions              : 0 
  SMPT Session      Used Memory  :             0     No of Allocs :             0     No of Frees  :             0  SMTP Config      Used Memory  :         14060     No of Allocs :            19     No of Frees  :            71   Total memory used :         14060
Heap Statistics of smtp:
          Total Statistics:
               Memory in use:          14060 bytes
                No of allocs:             19
                 No of frees:             71
         Config Statistics:
               Memory in use:          14060 bytes
                No of allocs:             19
                 No of frees:             71
===============================================================================

Memory Statistics of Stream on: Mon Feb 28 00:26:59 2022

Stream Session Statistics:
            Total sessions: 1
              TCP sessions: 0
       Active TCP sessions: 0
              UDP sessions: 1
       Active UDP sessions: 1
             ICMP sessions: 0
      Active ICMP sessions: 0
               IP sessions: 0
        Active IP sessions: 0
   TCP Memory Pool:
        Free Memory:                     0 bytes
        Used Memory:                     0 bytes
        Max Memory :                     0 bytes
   UDP Memory Pool:
        Free Memory:                     0 bytes
        Used Memory:                     0 bytes
        Max Memory :                     0 bytes
   ICMP Memory Pool:
        Free Memory:                     0 bytes
        Used Memory:                     0 bytes
        Max Memory :                     0 bytes
   IP Memory Pool:
        Free Memory:                     0 bytes
        Used Memory:                     0 bytes
        Max Memory :                     0 bytes
   Session Flow Memory Pool:
        Free Memory:                     0 bytes
        Used Memory:                     0 bytes
        Max Memory :                     0 bytes

Heap Statistics of stream:
          Total Statistics:
               Memory in use:        2072952 bytes
                No of allocs:             13
                 No of frees:              9
         Config Statistics:
               Memory in use:        2072952 bytes
                No of allocs:             13
                 No of frees:              9
===============================================================================

Memory Statistics of DCE at: Mon Feb 28 00:26:59 2022

dcerpc2 Preprocessor Statistics:
                Total sessions :    0
               Active sessions :    0
            Total SMB sessions :    0
            Total TCP sessions :    0
            Total UDP sessions :    0
    Total HTTP server sessions :    0
     Total HTTP proxy sessions :    0
Total Memory stats :
                 Current total :    52428800
                 Maximum total :    52515830
                  Total memcap :    0
                    Free total :    0
SMB Memory stats :
                 Current total :    52428800
                 Maximum total :    52428800
          Current session data :    52428800
          Maximum session data :    52428800
   Current segmentation buffer :    0
   Maximum segmentation buffer :    0
TCP Memory stats :
                 Current total :    0
                 Maximum total :    0
          Current session data :    0
          Maximum session data :    0
UDP Memory stats :
                 Current total :    0
                 Maximum total :    0
          Current session data :    0
          Maximum session data :    0
HTTP Memory stats :
                 Current total :    0
                 Maximum total :    0
          Current session data :    0
          Maximum session data :    0

Heap Statistics of dce:
          Total Statistics:
               Memory in use:              0 bytes
                No of allocs:            115
                 No of frees:            115
         Config Statistics:
               Memory in use:              0 bytes
                No of allocs:            115
                 No of frees:            115
===============================================================================

Memory Statistics of SIP on: Mon Feb 28 00:26:59 2022

    Total Sessions          : 0
    Current Active Sessions : 0


Heap Statistics of sip:
          Total Statistics:
               Memory in use:              0 bytes
                No of allocs:             22
                 No of frees:             22
         Config Statistics:
               Memory in use:              0 bytes
                No of allocs:             22
                 No of frees:             22
===============================================================================
POP Preprocessor Statistics
  Total sessions                : 0 
  Max concurrent sessions       : 0 
  Current sessions              : 0 
  POP Session      Used Memory  :             0     No of Allocs :             0     No of Frees  :             0  POP Config      Used Memory  :           449     No of Allocs :             3     No of Frees  :            18   Total memory used :           449
Heap Statistics of pop:
          Total Statistics:
               Memory in use:            449 bytes
                No of allocs:              3
                 No of frees:             18
         Config Statistics:
               Memory in use:            449 bytes
                No of allocs:              3
                 No of frees:             18
===============================================================================
IMAP Preprocessor Statistics
  Total sessions                : 0 
  Max concurrent sessions       : 0 
  Current sessions              : 0 
  IMAP Session      Used Memory  :             0     No of Allocs :             0     No of Frees  :             0  IMAP Config      Used Memory  :          1379     No of Allocs :             3     No of Frees  :            48   Total memory used :          1379
Heap Statistics of imap:
          Total Statistics:
               Memory in use:           1379 bytes
                No of allocs:              3
                 No of frees:             48
         Config Statistics:
               Memory in use:           1379 bytes
                No of allocs:              3
                 No of frees:             48
===============================================================================

Memory Statistics for File at:Mon Feb 28 00:26:59 2022

Total buffers allocated:           0          
Total buffers freed:               0          
Total buffers released:            0          
Total file mempool:                0          
Total allocated file mempool:      0          
Total freed file mempool:          0          
Total released file mempool:       0          

Heap Statistics of file:
          Total Statistics:
               Memory in use:            280 bytes
                No of allocs:              6
                 No of frees:              1
        Session Statistics:
               Memory in use:              0 bytes
                No of allocs:              1
                 No of frees:              1
        Mempool Statistics:
               Memory in use:            280 bytes
                No of allocs:              5
                 No of frees:              0
===============================================================================
Snort exiting
```