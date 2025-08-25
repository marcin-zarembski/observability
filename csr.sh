#!/bin/bash
# execution by 
# sh createCSR_light.sh DEV/VALIDATION/TEST ********** '*********' "https://artifactory.itcm.oneadr.net/cdp-tenant/fciait/elk"
# please put password in single quotes like
# sh createCSR.sh TEST SVC10525 '**********' "https://artifactory.itcm.oneadr.net/cdp-tenant/fciait/elk"

# Check if nodes are provided as arguments

if [ "$#" -eq 0 ]; then
  echo "Usage: $0 enviornment usernameArtifactory passwordArtifactory urlArtifactory"
fi

current_host_name_short=$(hostname -s)
enviornment=$1
usernameArtifactory=$2
passwordArtifactory=$3
urlArtifactory=$4

create_csr_and_key(){

local longname="$1"
local shortname="$2"
local enviornment=$3
local usernameArtifactory=$4
local passwordArtifactory=$5
local urlArtifactory=$6


echo "preparing ssh config file"

cat<<EOF >ssl_config
[req]
default_bits = 4096
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C=FI
ST=Helsinki
L=Helsinki
O=Nordea Bank Abp
OU=Nordea IT
CN=${longname}

[ req_ext ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName =@alt_names


[ alt_names ]
DNS.1 = ${longname}
DNS.2 = ${shortname}
EOF

		openssl genrsa -out ${shortname}.key 4096

		openssl req -config ssl_config -new -key ${shortname}.key -out ${shortname}.csr
		
		echo "csr file name is ${shortname}.csr"
		curl -X PUT -u ${usernameArtifactory}:"${passwordArtifactory}" -T ${shortname}.csr ${urlArtifactory}/csrFiles/${enviornment}/${shortname}.csr
		
		echo "key file name is ${shortname}.key"
		curl -X PUT -u ${usernameArtifactory}:"${passwordArtifactory}" -T ${shortname}.key ${urlArtifactory}/keyFiles/${enviornment}/${shortname}.key
}



for server in $(cat server_list_$1); do
	if [ "$server" != "$current_host_name_short" ]; then
		echo connecting for remote execution
		echo "Executing for $server" 

		ssh ${server} <<ENDSSH
		$(typeset -f)
		create_csr_and_key $server.oneadr.net $server $enviornment $usernameArtifactory "${passwordArtifactory}" $urlArtifactory

ENDSSH

	else
		echo executing locally
		echo "Executing for $server"
		
		create_csr_and_key $server.oneadr.net $server $enviornment $usernameArtifactory "${passwordArtifactory}" $urlArtifactory
		
	fi
done
