set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)

# CI builds and tests Release only. The default x64-windows triplet also
# builds the debug libraries, which repeats the OpenSSL compile.
set(VCPKG_BUILD_TYPE release)
