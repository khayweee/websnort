build_docker_snort:
	docker-compose build docker-snort

start_docker_snort:
	docker-compose run --rm docker-snort