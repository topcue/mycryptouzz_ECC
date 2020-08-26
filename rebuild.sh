#!/bin/sh

clang++-8 ecc_ed25519.cpp -o ecc_ed25519 -I /home/topcue/workspace/cryptopp -L /home/topcue/workspace/cryptopp -l cryptopp -fsanitize=address,fuzzer

# EOF

