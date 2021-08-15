#!/bin/sh
gnome-terminal -- /bin/sh -c "g++ beacon.cpp -lssl -lcrypto -o beacon"
gnome-terminal -- /bin/sh -c "g++ Blockchain.cpp -lssl -lcrypto -lpthread -Wno-deprecated -o bc"
