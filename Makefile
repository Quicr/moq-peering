# This is just a convenience Makefile to avoid having to remember
# all the CMake commands and their arguments.

# Set CMAKE_GENERATOR in the environment to select how you build, e.g.:
#   CMAKE_GENERATOR=Ninja

BUILD_JOBS ?= 4
BUILD_DIR ?= build
CLANG_FORMAT = clang-format -i

PROJECTNAME := moq-peering

.PHONY: all build build-prep clean cclean test cert format help

# -----------------------------------------
# Help/other targets
# -----------------------------------------
.PHONY: help
help: Makefile
	@echo
	@echo " Choose a command run "$(PROJECTNAME)":"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'

# -----------------------------------------
# Commands
# -----------------------------------------
all: build

build-prep: CMakeLists.txt
	cmake -S . -B${BUILD_DIR} -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_BUILD_TYPE=Release -DMOQ_PEERING_BUILD_TESTS=ON -DMOQ_PEERING_BUILD_EXAMPLES=ON

## build: Build the library, tests, and examples
build: build-prep
	cmake --build ${BUILD_DIR} -j ${BUILD_JOBS}

## test: Build and run the unit tests
test: build
	ctest --test-dir ${BUILD_DIR} --output-on-failure

## clean: cmake clean - soft clean
clean:
	cmake --build ${BUILD_DIR} --target clean

## cclean: Deep clean/wipe
cclean:
	rm -rf ${BUILD_DIR}

## cert: Create a development certificate and key in the build directory
cert:
	@mkdir -p ${BUILD_DIR}
	@echo "Creating a self-signed development certificate in ${BUILD_DIR}"
	@echo "ECDSA P-256, SHA-256, 365 days. For development and tests only."
	@openssl req -nodes -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -days 365 \
		-subj "/C=US/ST=CA/L=San Jose/O=Cisco/CN=test.m10x.org" \
		-keyout ${BUILD_DIR}/server-key.pem -out ${BUILD_DIR}/server-cert.pem
	@echo "Certificate: ${BUILD_DIR}/server-cert.pem"
	@echo "Private key: ${BUILD_DIR}/server-key.pem"

## format: Format c/c++ code
format:
	find include src test examples \( -iname "*.h" -o -iname "*.cc" \) -print0 | xargs -0 ${CLANG_FORMAT}
