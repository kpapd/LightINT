#ex. sudo bash runexp.sh dlint1 1/1 0 3281 30
#!/bin/bash
if [ -z "$1" ]
  then
    echo "Argument missing: Usage runexp [type&numOfTelemetryValuesPerPacket] [referenceLabel=X] [puthUpdate=0/1] [bfSize] [PU time] ex. sudo sh runexp.sh dlint 100% 0 4081 0 30"
    exit
fi
typ=$1
#echo ${typ:0:2}

mn -c
rm -f *.pcap
rm -rf build pcaps logs
mkdir -p build pcaps logs

if [ ! -z "$4" ] 
  then
    sed -i 's/^#define BLOOM_FILTER_ENTRIES .*$/#define BLOOM_FILTER_ENTRIES '$4/ $1val.p4
fi
cp $1val.p4 base.p4

#Compiles a P4 program and outputs p4info.txt (=P4Runtime control plane API description) and base.json (json describing the p4 program)
p4c-bm2-ss --p4v 16 --p4runtime-files build/base.p4.p4info.txt -o build/base.json base.p4
python3 ./experiment.py -t topology.json -b simple_switch_grpc -v $1 -s $2 -f $4 -u $3 -r $5
