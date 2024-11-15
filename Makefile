ARTIFACT_ID=remote-dogu-descriptor-lib
VERSION=0.0.0

MAKEFILES_VERSION=9.3.2
.DEFAULT_GOAL:=help

include build/make/variables.mk
include build/make/self-update.mk
include build/make/dependencies-gomod.mk
include build/make/build.mk
include build/make/test-common.mk
include build/make/test-unit.mk
include build/make/static-analysis.mk
include build/make/clean.mk
include build/make/release.mk
include build/make/mocks.mk
