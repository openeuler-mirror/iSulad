# devicemapper的环境准备

1. 安装lvm逻辑卷管理包：

```bash
# apt-get install lvm2
```

2. 查看当前主机上可用块设备：

```bash
# lsblk
```

3. 执行`isulad_lvm_conf.sh`配置isulad-thinpool:

```bash
#sh -x isulad_lvm_conf.sh sda8
```

`isulad_lvm_conf.sh`中的内容如下：

```shell
#!/bin/bash
current_dir=$(cd `dirname $0` && pwd)
disk="/dev/$1"

rm -rf /var/lib/isulad/*
dmsetup remove_all
lvremove -f isulad/thinpool
lvremove -f isulad/thinpoolmeta
vgremove -f isulad
pvremove -f $disk
mount | grep $disk | grep /var/lib/isulad
if [ x"$?" == x"0" ];then
    umount /var/lib/isulad
fi
echo y | mkfs.ext4 $disk

touch /etc/lvm/profile/isulad-thinpool.profile
cat > /etc/lvm/profile/isulad-thinpool.profile <<EOF
activation {
thin_pool_autoextend_threshold=80
thin_pool_autoextend_percent=20
}
EOF
pvcreate -y $disk
vgcreate isulad $disk
echo y | lvcreate --wipesignatures y -n thinpool isulad -l 80%VG
echo y | lvcreate --wipesignatures y -n thinpoolmeta isulad -l 1%VG
lvconvert -y --zero n -c 512K --thinpool isulad/thinpool --poolmetadata isulad/thinpoolmeta
lvchange --metadataprofile isulad-thinpool isulad/thinpool
lvs -o+seg_monitor
exit 0
```

4. 配置`isulad`

   在`/etc/isulad/daemon.json`中配置`storage-driver`和`storage-opts`：

   ```txt
   "storage-driver": "devicemapper",
   "storage-opts": [
           "dm.thinpooldev=/dev/mapper/isulad-thinpool",
           "dm.fs=ext4",
           "dm.min_free_space=10%"
    ],
   ```

5. 重启`isulad`。

   ```bash
   $ sudo systemctl restart isulad
   ```