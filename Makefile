all:
	#none



local_install:
	@for f in $(shell find usr/ -type f); do \
	    dest=`dirname $$f` ; \
	    mkdir -p "/$$dest"; \
	    echo "install -m 644 $$f /$$dest/" ;\
	    install -m 644 "$$f" "/$$dest/" ;\
	done	


local_uninstall:
	@for f in $(shell find usr/ -type f); do \
	    dest=`dirname $$f` ; \
	    echo "rm /$$f" ;\
	    rm -v "/$$f" ;\
	done	
	
