	#!/bin/bash

###############################################################################
#																			  #
# Aluno: Renato Gomes Silvério												  #
# Periodo: 4º															      #  
# Curso: Superior de Tecnologia em Rede de Computadores						  #
# Aplicações: SNORT(IDS)													  #
# Sistema Operacional: Debian 9 (stretch)    								  #
# Data:13/05/2019														      #
#																			  #		
###############################################################################

#OBS: Mude a inteface para a que desejar monitorar no final do arquivo Linha 124

#Comando para monitorar uma rede especifica:

# snort -d -l /var/log/snort/ -h 10.0.0.0/24 -A console -c /etc/snort/snort.conf

## =================================================
## Baixando Dependencias Necessarias:
## =================================================

apt-get update

apt-get install -y git gcc make libpcre3-dev zlib1g-dev libluajit-5.1-dev libpcap-dev openssl libssl-dev libnghttp2-dev libdumbnet-dev bison flex libdnet

## =====================================================
## Criando Diretorio para baixar o SNORT e Dependencias:
## =====================================================

mkdir ~/snort_src && cd ~/snort_src

## =================================================
## Baixando, Extraindo e preparando o daq
## =================================================

wget https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz

tar -xvzf daq-2.0.6.tar.gz
cd daq-2.0.6

./configure && make && make install

## =================================================
## Baixando o SNORT e compilando:
## =================================================

cd ~/snort_src

wget https://www.snort.org/downloads/snort/snort-2.9.13.tar.gz

tar -xvzf snort-2.9.13.tar.gz

cd ~/snort_src/snort-2.9.13

./configure --enable-sourcefire && make && make install

## =================================================
## Atualizando as bibliotecas compartilhadas: 
## =================================================

ldconfig


## =================================================
## criar um link simbólico para /usr/sbin/snort:
## =================================================

ln -s /usr/local/bin/snort /usr/sbin/snort

## =======================================================================================
##  criar um novo usuário sem privilégios e um novo grupo de usuários para o daemon rodar:
## =======================================================================================

groupadd snort
useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort


mkdir -p /etc/snort/rules
mkdir /var/log/snort
mkdir /usr/local/lib/snort_dynamicrules

wget https://www.snort.org/rules/community -O ~/community.tar.gz

tar -xvf ~/community.tar.gz -C ~/

cp ~/community-rules/* /etc/snort/rules

chmod -R 5775 /etc/snort
chmod -R 5775 /var/log/snort
chmod -R 5775 /usr/local/lib/snort_dynamicrules
chown -R snort:snort /etc/snort
chown -R snort:snort /var/log/snort
chown -R snort:snort /usr/local/lib/snort_dynamicrules


touch /etc/snort/rules/white_list.rules
touch /etc/snort/rules/black_list.rules
touch /etc/snort/rules/local.rules

cp ~/snort_src/snort-2.9.13/etc/*.conf* /etc/snort
cp ~/snort_src/snort-2.9.13/etc/*.map /etc/snort

git clone https://github.com/renatowow14/SNORT.git

cd SNORT

cp snort.conf /etc/snort/

RULES01='
alert icmp any any -> $HOME_NET any (msg:"ICMP test"; sid:10000001; rev:001;)
alert tcp any any -> any any (flags:S; msg:"NMAP TCP SYN"; sid: 1231213;)
alert tcp any any -> $HOME_NET any (msg:”TCP Port Scanning”; detection_filter:track by_src, count 30, seconds 60; sid:1000006; rev:2;)' 
echo "$RULES01" >> /etc/snort/rules/community.rules

snort -T -c /etc/snort/snort.conf

touch /lib/systemd/system/snort.service

RULES02='
[Unit]
Description=Snort NIDS Daemon
After=syslog.target network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snort -q -u snort -g snort -c /etc/snort/snort.conf -i enp0s3
[Install]
WantedBy=multi-user.target
'

echo "$RULES02" > /lib/systemd/system/snort.service

systemctl daemon-reload

systemctl start snort

systemctl status snort