# websnort
websnort-api
This project aim to create a graphical user interface ro run PCAP files on a set of snort rule(s).  

```
# Docker build
docker build -t docker-snort .

# Docker run interactive shell
docker run -it --rm docker-snort /bin/bash
```

Docker-Compose
```
docker-compose run --rm docker-snort
```

For testing whether it works. Add this rule into /etc/snort/rules/local.rules
```
alert icmp any any -> any any (msg: "Pinging...."; sid:1000004; )
```
Running snort and alerts output to the console (screen)
```
snort -i eth0 -c /etc/snort/etc/snort.conf -A console
```

# 1. Common Dev Commands
### 1.1 Some Useful Docker Commands
```
# Remove all stopped containers
docker container prune 

# Remove all orphaned image
docker image prune

# Remove all unused networks
docker network prune
```

### 1.2 Some TCPDUMP commands
```
# Record PCAP
# -s 0 for maximum file capture size
# -c n for n number of packets 
sudo tcpdump -i eth0 -s 0 -w output.pcap
```

### 1.3 Snort Commands
Note -l replace default output directory with directory specified
```
# Read PCAP
snort -c /etc/snort/etc/snort.conf -r /etc/snort/recorded_pcaps/icmp_8888.pcap -l /etc/snort/logs

# Read from interface
snort -i eth0 -c /etc/snort/etc/snort.conf -A console -l /etc/snort/logs
```

# 2. Snort Conf
### 2.1 Rules Performance

Microsecs indicate the total time spent on evaluating a given rule
A high **Avg/Check** is a poor performing rule, that most likely contains PCRE. High Checks and low Avg/Check is
usually an any->any rule with few rule options and no content. Quick to check, the few options may or may not match.
```
# Snort Rules Performance Profiling
# /etc/snort/snort.conf
config profile_rules: print all, sort avg_ticks filename rules_stats.txt

# file output to /var/log/snort/rules_stats.txt.timestamp
# Rule Profile Statistics (all rules)
# ==========================================================
#   Num      SID GID Rev     Checks   Matches    Alerts           Microsecs  Avg/Check  Avg/Match Avg/Nonmatch   Disabled
#   ===      === === ===     ======   =======    ======           =========  =========  ========= ============   ========
#     1  1000004   1   0          8         4         4                   0        0.1        0.2          0.0          0
```

### 2.2 Output
Recommended format unified2

When a configured limit is reached, the current log is closed and a new log is opened with a UNIX timestamp appended
to the configured log name.

```
# /etc/snort/snort.conf
output unified2: filename snort.log, limit 128mb, nostamp, mpls_event_types, vlan_event_types

# Convert unified2 file to pcap for analysis in packet analysis software (e.g. Wireshark)
u2boat -t pcap <infile> <outfile>
```

