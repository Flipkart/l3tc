EXTRA_DIST = l3tc_routeup.sh

scriptsdir = $(prefix)/libexec/$(PACKAGE)
scripts_DATA = $(EXTRA_DIST)

install-data-hook:
	chmod -R u+x $(prefix)/libexec/$(PACKAGE)
