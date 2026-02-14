.PHONY: build clean

build:
	uv run python build.py

clean:
	rm -rf dist
