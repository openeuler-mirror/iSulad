# devicemapper environment preparation

1. Install the lvm logical volume management package:

```shell
# apt-get install lvm2
```

2. View available block devices on the host:

```shell
# lsblk
```

3. Use `isulad_lvm_conf.sh` to configure isulad-thinpool

```sh
#sh -x isulad_lvm_conf.sh sda8
```

The contents of `isulad_lvm_conf.sh` are as follows:

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

4. Configure `isulad`

   Configure the `storage-driver` and `storage-opts`  in `/etc/isulad/daemon.json`:

```txt
"storage-driver": "devicemapper",
"storage-opts": [
        "dm.thinpooldev=/dev/mapper/isulad-thinpool",
        "dm.fs=ext4",
        "dm.min_free_space=10%"
 ],
```

5. Restart `isulad`.

   ```bash
   $ sudo systemctl restart isulad
   ```

