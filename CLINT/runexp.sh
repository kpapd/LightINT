#ex. sudo bash runexp.sh clint1 1/1 0 3281
#!/bin/bash
if [ -z "$1" ]
  then
    echo "Argument missing: Usage runexp [type&numOfTelemetryValuesPerPacket] [percentLabel=X] [puthUpdate=0/1] [bfSize] ex. sudo sh runexp.sh clint1 100% 0 4081"
    exit
fi

echo $PATH
pkill -f -9 'python3 p4_*'
ps aux |grep 'python3 p4_'

mn -c
rm -f *.pcap
rm -rf build pcaps logs
mkdir -p build pcaps logs

cp $1val.p4 base.p4

#Compiles a P4 program and outputs p4info.txt (=P4Runtime control plane API description) and base.json (json describing the p4 program)
p4c-bm2-ss --p4v 16 --p4runtime-files build/base.p4.p4info.txt -o build/base.json base.p4
python3 ./expirament.py -t topology.json -b simple_switch_grpc -v $1 -s $2 -u $3
