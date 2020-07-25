#!/bin/sh
#######################################################################
##- @Copyright (C) Huawei Technologies., Ltd. 2020. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description: install isulad-thinpool
##- @Author: gaohuatao
##- @Create: 2020-06-20
#######################################################################
set -x

dev_disk="/dev/$1"
isulad_daemon_file="/etc/isulad/daemon.json"

systemctl restart lvm2-lvmetad.service
systemctl restart systemd-udevd.service
udevadm control --reload-rules && udevadm trigger

dmsetup remove_all
lvremove -f isulad/thinpool
lvremove -f isulad/thinpoolmeta
vgremove -f isulad
pvremove -f $dev_disk

echo y | mkfs.ext4 $dev_disk
mkdir -p /etc/lvm/profile
touch /etc/lvm/profile/isulad-thinpool.profile
cat > /etc/lvm/profile/isulad-thinpool.profile <<EOF
activation {
thin_pool_autoextend_threshold=80
thin_pool_autoextend_percent=20
}
EOF
pvcreate -y $dev_disk
vgcreate isulad $dev_disk
echo y | lvcreate --wipesignatures y -n thinpool isulad -l 80%VG
echo y | lvcreate --wipesignatures y -n thinpoolmeta isulad -l 1%VG
lvconvert -y --zero n -c 512K --thinpool isulad/thinpool --poolmetadata isulad/thinpoolmeta
lvchange --metadataprofile isulad-thinpool isulad/thinpool
lvs -o+seg_monitor

sed -i 's/\"storage\-driver\"\: \"overlay2\"/\"storage\-driver\"\: \"devicemapper\"/g' $isulad_daemon_file
sed -i '/    \"storage-opts\"\: \[/{n;d}' $isulad_daemon_file
sed -i '/    \"storage-opts\"\: \[/a\    \"dm\.thinpooldev\=\/dev\/mapper\/isulad\-thinpool\",\n    \"dm\.fs\=ext4\"\,\n    \"dm\.min\_free\_space\=10\%\"' $isulad_daemon_file


