cmake_minimum_required(VERSION 2.8)
project(digest)

find_library(cloudhsmpkcs11 STATIC)

include_directories("../common")
include_directories("../pkcs11_headers")

add_executable(digest digest.c)
target_link_libraries(digest cloudhsmpkcs11)
