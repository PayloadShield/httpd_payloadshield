# sudo apt install build-essential apache2-dev libssl-dev -y
rm -rf httpd_payloadshield-main main.zip
wget https://github.com/PayloadShield/httpd_payloadshield/archive/refs/heads/main.zip
unzip main.zip
cd httpd_payloadshield-main
make clean
make
make install
# make test 