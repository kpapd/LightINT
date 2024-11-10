# LightINT
The repository contains the code to implement three distinct In-Band Network Telemetry (INT) methods using P4-enabled switches.

<ul>
  <li>DLINT: Deterministic Lightweight INT</li>
  <li>PLINT: Probabilistic Lightweight INT</li>
  <li>CLINT: Controller-assisted Lightweight INT</li>  
</ul>

The methods are described in the following two scientific papers. They utilize BMv2 software switch.

https://ieeexplore.ieee.org/document/10206040

https://ieeexplore.ieee.org/document/10493019

# Installation

To install you need a fresh instance of Ubuntu 20. A desktop version would be prefferable since GUI tools (such as Wireshark) can be used.

Open a terminal and issue the following commands. Keep the directory structure.

<ul>
  <li>sudo apt update</li>
  <li>sudo apt upgrade</li>
  <li>sudo apt install git</li>
  <li>git clone https://github.com/jafingerhut/p4-guide.git</li>
  <li>./p4-guide/bin/install-p4dev-v5.sh (This should take some minutes)</li>
  <li>sudo apt install d-itg</li>
  <li>git clone https://github.com/p4lang/tutorials.git</li>
  <li>cd tutorials</li>
  <li>git reset --hard aa58e1247d69455e7e330273edd00c68e0810572</li>
  <li>cd ..</li>
</ul>

