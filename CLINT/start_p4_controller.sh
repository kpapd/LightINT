#!/bin/sh

sudo python3 p4_controller.py \
    --p4info ./build/base.p4.p4info.txt \
    --bmv2-json ./build/base.json 
