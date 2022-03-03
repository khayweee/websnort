build_docker_snort:
	docker-compose build docker-snort

start_docker_snort_terminal:
	docker-compose run --entrypoint "/bin/bash" --rm docker-snort 

start_api:
	docker-compose up docker-snort