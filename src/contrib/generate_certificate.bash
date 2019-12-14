#######################################################################
##- @Copyright (C) Huawei Technologies., Ltd. 2017-2019. All rights reserved.
# - iSulad licensed under the Mulan PSL v1.
# - You can use this software according to the terms and conditions of the Mulan PSL v1.
# - You may obtain a copy of Mulan PSL v1 at:
# -     http://license.coscl.org.cn/MulanPSL
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v1 for more details.
##- @Description: generate cetification
##- @Author: wujing
##- @Create: 2019-04-25
#######################################################################
#!/bin/bash
set -e
echo -n "Enter pass phrase:"
read password
echo -n "Enter public network ip:"
read publicip
echo -n "Enter host:"
read HOST

echo " => Using hostname: tcp://$publicip:2375, You MUST connect to iSulad using this host!"

mkdir -p $HOME/.iSulad
cd $HOME/.iSulad
rm -rf $HOME/.iSulad/*

echo " => Generating CA key"
openssl genrsa -passout pass:$password -aes256 -out ca-key.pem 4096
echo " => Generating CA certificate"
openssl req -passin pass:$password -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem -subj "/C=CN/ST=zhejiang/L=hangzhou/O=Huawei/OU=iSulad/CN=iSulad@huawei.com"
echo " => Generating server key"
openssl genrsa -passout pass:$password -out server-key.pem 4096
echo " => Generating server CSR"
openssl req -passin pass:$password -subj /CN=$HOST -sha256 -new -key server-key.pem -out server.csr
echo subjectAltName = DNS:$HOST,IP:$publicip,IP:127.0.0.1 >> extfile.cnf
echo extendedKeyUsage = serverAuth >> extfile.cnf
echo " => Signing server CSR with CA"
openssl x509 -req -passin pass:$password -days 365 -sha256 -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -extfile extfile.cnf
echo " => Generating client key"
openssl genrsa -passout pass:$password -out key.pem 4096
echo " => Generating client CSR"
openssl req -passin pass:$password -subj '/CN=client' -new -key key.pem -out client.csr
echo " => Creating extended key usage"
echo extendedKeyUsage = clientAuth > extfile-client.cnf
echo " => Signing client CSR with CA"
openssl x509 -req -passin pass:$password -days 365 -sha256 -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out cert.pem -extfile extfile-client.cnf
rm -v client.csr server.csr extfile.cnf extfile-client.cnf
chmod -v 0400 ca-key.pem key.pem server-key.pem
chmod -v 0444 ca.pem server-cert.pem cert.pem
if [ -d "/etc/profile.d" ]; then
  echo " => Creating profile.d/iSulad"
  sudo bash -c "echo '#!/bin/bash 
  export ISULAD_HOST=tcp://$publicip:2375
  export ISULAD_CERT_PATH=$HOME/.iSulad
  export ISULAD_TLS_VERIFY=1' > /etc/profile.d/iSulad.sh"
  sudo chmod +x /etc/profile.d/iSulad.sh
  source /etc/profile.d/iSulad.sh
else
  echo " => WARNING: No /etc/profile.d directoy on your system."
  echo " =>   You will need to set the following environment variables before running the iSulad client(lcrc):"
  echo " =>   ISULAD_HOST=tcp://$publicip:2375"
  echo " =>   ISULAD_CERT_PATH=$HOME/.iSulad"
  echo " =>   ISULAD_TLS_VERIFY=1"
fi

OPTIONS="--tlsverify --tlscacert=$HOME/.iSulad/ca.pem --tlscert=$HOME/.iSulad/server-cert.pem --tlskey=$HOME/.iSulad/server-key.pem -H=0.0.0.0:2375"
if [ -f "/lib/systemd/system/lcrd.service" ]; then
  echo " => Configuring /lib/systemd/system/lcrd.service"
  SERVICE_BACKUP="/lib/systemd/system/lcrd.service.$(date +"%s")"
  mv /lib/systemd/system/lcrd.service $SERVICE_BACKUP
  sudo sh -c "echo '# The following line was added by iSulad TLS configuration script
  OPTIONS=\"$OPTIONS\"
  # A backup of the old file is at $SERVICE_BACKUP.' >> /etc/sysconfig/iSulad"
  echo " => Backup file location: $SERVICE_BACKUP"
else
  echo " => WARNING: No /etc/sysconfig/iSulad file found on your system."
  echo " =>   You will need to configure your iSulad daemon with the following options:"
  echo " =>   $OPTIONS" 
fi

export ISUALD_HOST=tcp://$publicip:2375
export ISULAD_CERT_PATH=$HOME/.iSulad
export ISULAD_TLS_VERIFY=1
echo " => Done! You just need to restart iSulad for the changes to take effect"

