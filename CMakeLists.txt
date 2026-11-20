cmake_minimum_required(VERSION 3.16)
project(antitout_qnx C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -O2)

# liboqs built with: -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;SIG_slh_dsa_pure_sha2_128s" -DOQS_USE_OPENSSL=OFF
set(OQS_PREFIX "" CACHE PATH "Install prefix of liboqs for this target")
find_path(OQS_INCLUDE oqs/oqs.h HINTS ${OQS_PREFIX}/include REQUIRED NO_CMAKE_FIND_ROOT_PATH)
find_library(OQS_LIB NAMES liboqs.a oqs HINTS ${OQS_PREFIX}/lib REQUIRED NO_CMAKE_FIND_ROOT_PATH)

add_library(bnjournal STATIC src/sha3.c src/journal.c)
target_include_directories(bnjournal PUBLIC include ${OQS_INCLUDE})
target_link_libraries(bnjournal PUBLIC ${OQS_LIB})

add_executable(bn_keys outils/bn_keys.c)
target_link_libraries(bn_keys bnjournal)
add_executable(bn_verify outils/bn_verify.c)
target_link_libraries(bn_verify bnjournal)
add_executable(bn_list outils/bn_list.c)
target_link_libraries(bn_list bnjournal)
add_executable(bn_soi outils/bn_soi.c qnx/soi.c)
target_link_libraries(bn_soi bnjournal)

if(TRUE)  # also on QNX: the tests run on the target
  enable_testing()
  add_executable(test_journal tests/test_journal.c)
  target_link_libraries(test_journal bnjournal)
  add_test(NAME journal COMMAND test_journal)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "QNX")
  foreach(p boitenoire doseur antitout intrus)
    add_executable(${p} qnx/${p}.c qnx/soi.c)
    target_link_libraries(${p} bnjournal)
  endforeach()
endif()
