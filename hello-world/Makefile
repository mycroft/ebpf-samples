all: clean build

build:
	go generate
	go build

clean:
	rm -f *.o hello-world

run: build
	sudo ./hello-world

.PHONY: all build clean run
