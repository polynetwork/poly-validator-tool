COMMIT ?= main

clean:
	rm -rf *.8 *.o *.out *.6 *exe
	rm -rf poly-validator-tool docker/payload docker/build
	docker container rm -f go-tool-temp
	docker rmi -f go-tool-build


build: clean
	@echo "Building poly-validator-tool binary in container"
	docker build --no-cache --build-arg commit=$(COMMIT) -t go-tool-build -f ./Dockerfile .
	docker container create --name go-tool-temp go-tool-build
	docker container cp go-tool-temp:/workspace/poly-validator-tool/poly-validator-tool .
	sha256sum poly-validator-tool