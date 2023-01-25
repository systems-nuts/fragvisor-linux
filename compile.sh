#!/bin/bash
sed -i 's/#define CONFIG_POPCORN_ORIGIN_NODE//' include/popcorn/debug.h && make -j32 && make modules && sudo make modules_install && sudo make install
