
target-y = \
	address \
	key_liboqs_tests

common_cflags = \
	-DHAVE_CONFIG_H \
	-Wno-unused-parameter \
	-I${BSPROOTFS}/include \
	-I${BSPROOTFS}/include/bitcoin \
	$(shell PKG_CONFIG_PATH=${BSPROOTFS}/lib/pkgconfig pkg-config openssl --cflags)

common_cxxflags = \
	${common_cflags} \
	-std=c++11

common_libraries = \
	${BSPROOTFS}/lib \

common_ldflags = \
	-lbitcoin_server \
	-lbitcoin_common \
	-lbitcoin_consensus \
	-lbitcoin_util \
	-lbitcoin_crypto_base \
	-lsecp256k1 \
	-lunivalue \
	-lboost_system-mt \
	-lboost_filesystem-mt \
	-lboost_program_options-mt \
	-lboost_thread-mt \
	-lboost_chrono-mt \
	-loqs \
	$(shell PKG_CONFIG_PATH=${BSPROOTFS}/lib/pkgconfig pkg-config openssl --static --libs)

# address
address_files-y     = address.cpp bitcoin.cpp util.c
address_cflags-y    = ${common_cflags}
address_cxxflags-y  = ${common_cxxflags}
address_libraries-y = ${common_libraries}
address_ldflags-y   = ${common_ldflags}

# key creation
key_liboqs_tests_files-y     = key_liboqs_tests.cpp bitcoin.cpp util.c
key_liboqs_tests_cflags-y    = ${common_cflags}
key_liboqs_tests_cxxflags-y  = ${common_cxxflags}
key_liboqs_tests_libraries-y = ${common_libraries}
key_liboqs_tests_ldflags-y   = ${common_ldflags}

include Makefile.lib
