#!/bin/bash

# Title:        Wake on Lan
# Description:  Wake On Lan with Python
# Author:       Hak5

# Configuration

# MAC addresses, separated by spaces
WOL_TARGETS="11:22:33:44:55:66 AA:BB:CC:DD:EE:FF"

# How often do we wake up systems, in seconds?
WOL_INTERVAL=30




# NAT mode
NETMODE NAT

# Set the LED
LED G SINGLE

while true; do
    # Toggle the LED, send the WoL
    LED W SOLID
    python /root/payloads/$(SWITCH)/python_wol.py ${WOL_TARGETS}
    
    # Wait one second for the LED to be visible
    sleep 1
    
    # Reset the LED
    LED G SINGLE
    
    # Wait the wakeup interval
    sleep ${WOL_INTERVAL}
done