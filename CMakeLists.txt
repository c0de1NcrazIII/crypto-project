cmake_minimum_required(VERSION 3.16)
project(crypto_project CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/src)

# Common sources
set(CORE_SRC
    src/core/BitPermutation.cpp
)

set(RIJNDAEL_SRC
    src/rijndael/GaloisField.cpp
    src/rijndael/RijndaelCipher.cpp
)

set(IDEA_SRC
    src/idea/IdeaCipher.cpp
)

# demo_symmetric: DES, 3DES, DEAL + modes
add_executable(demo_symmetric
    demo/demo_symmetric.cpp
    ${CORE_SRC}
)
target_link_libraries(demo_symmetric PRIVATE pthread)

# demo_rijndael: GF(2^8) + Rijndael + modes
add_executable(demo_rijndael
    demo/demo_rijndael.cpp
    ${CORE_SRC}
    ${RIJNDAEL_SRC}
)
target_link_libraries(demo_rijndael PRIVATE pthread)

# demo_idea: IDEA + modes
add_executable(demo_idea
    demo/demo_idea.cpp
    ${CORE_SRC}
    ${IDEA_SRC}
)
target_link_libraries(demo_idea PRIVATE pthread)

# demo_rsa: number theory, primality, RSA, Wiener
find_library(GMP_LIB gmp HINTS /usr/local/lib /opt/homebrew/lib)
find_library(GMPXX_LIB gmpxx HINTS /usr/local/lib /opt/homebrew/lib)
find_path(GMP_INCLUDE gmpxx.h HINTS /usr/local/include /opt/homebrew/include)

set(RSA_SRC
    src/math/NumberTheory.cpp
    src/primality/FermatTest.cpp
    src/primality/SolovayStrassenTest.cpp
    src/primality/MillerRabinTest.cpp
    src/rsa/RsaService.cpp
    src/rsa/WienerAttack.cpp
)

add_executable(demo_rsa
    demo/demo_rsa.cpp
    ${RSA_SRC}
)
target_include_directories(demo_rsa PRIVATE ${GMP_INCLUDE})
target_link_libraries(demo_rsa PRIVATE ${GMP_LIB} ${GMPXX_LIB})
