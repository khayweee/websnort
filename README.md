# websnort
websnort-api

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

# Some Useful Docker Commands
```
# Remove all stopped containers
docker container prune 

# Remove all orphaned image
docker image prune

# Remove all unused networks
```