all:
	$(info 🌉 Building sources)
	@$(MAKE) -s -C src
	@ls -lh src/liblongfellow-zk.a | awk '{printf("🌉 %s %s\n",$$5,$$9)}'

import-vendor: vendor/longfellow-zk
	$(info 🌉 Importing source from upstream)
	@bash scripts/import_upstream.sh vendor/longfellow-zk

vendor/longfellow-zk:
	$(info 🌉 Cloning upstreaming from google/longfellow-zk)
	@mkdir -p vendor
	git clone https://github.com/google/longfellow-zk vendor/longfellow-zk

clean-vendor:
	$(info 🌉 Clean up build and all imported vendor sources)
	@bash scripts/import_upstream.sh clean

clean:
	@$(MAKE) -C src clean
