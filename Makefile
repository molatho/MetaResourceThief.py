.PHONY: submodules install test build docker clean

submodules:
	git submodule update --init --recursive

install:
	python -m pip install ./packaging -e ./resourcehacker[dev] -e ./metatwin[dev] -e ./metaresourcethief[dev]

test:
	cd resourcehacker && python -m pytest
	cd metatwin && python -m pytest
	cd metaresourcethief && python -m pytest

build:
	python scripts/build_exes.py

docker:
	docker build -t resourcehacker .

clean:
	rm -rf build dist *.spec resourcehacker/*.egg-info metatwin/*.egg-info metaresourcethief/*.egg-info packaging/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
