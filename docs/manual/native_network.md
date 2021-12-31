# Native Network Manual

This manual is mainly about how to use native network for iSulad community developers and users.

## Compile

The native network code is isolated by compilation macro `ENABLE_NATIVE_NETWORK`, and it is enabled by default. For the installation of the dependent environment of iSulad, please refer to the document `docs/build_guide_zh.md`, and it will not be repeated here. The following only describes the compilation of iSulad.

```bash
$ cd iSulad
$ rm -rf build && mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j $(nproc)
$ sudo -E make install
```

## Network Plugin

The natvie netwrok needs to install CNI plugin binary. The open source repository address is `https://github.com/containernetworking/plugins`. It is recommended to install the CNI plugin `v0.9.0` version and above. Here is an example of the latest v1.0.1 version when the manual was released.

```bash
$ wget https://github.com/containernetworking/plugins/releases/download/v1.0.1/cni-plugins-linux-amd64-v1.0.1.tgz
$ mkdir -p /opt/cni/bin/
$ tar -zxvf cni-plugins-linux-amd64-v1.0.1.tgz -C /opt/cni/bin/
```

## Start iSulad

Modify `isulad daemon.json` and config cni

```bash
$ vim /etc/isulad/daemon.json
	...
    "cni-bin-dir": "/opt/cni/bin",
    "cni-conf-dir": "/etc/cni/net.d",
    ...

# start isulad
$ isulad
```

`cni-bin-dir` is the cni binary directory. If it is not configured, the default value is `/opt/cni/bin`. `cni-conf-dir` is the network conflist directory. If it is not configured, the default value is `/etc/cni/net.d`. If you want to use default value, you can start isulad directly without config the `daemon.json`.

## Use native network

The use of native network is similar to that of docker. Here are some simple operation.

### Create network

```bash
$ isula network create cni0
cni0

$ isula network ls
NAME                 VERSION         PLUGIN
cni0                 0.4.0           bridge,portmap,firewall

$ isula network inspect cni0
[
    {
        "cniVersion": 0.4.0,
        "name": cni0,
        "plugins": [
            {
                "type": bridge,
                "bridge": isula-br0,
                "isGateway": true,
                "ipMasq": true,
                "hairpinMode": true,
                "ipam": {
                    "type": host-local,
                    "routes": [
                        {
                            "dst": 0.0.0.0/0
                        }
                    ],
                    "ranges": [
                        [
                            {
                                "subnet": 192.168.0.0/24,
                                "gateway": 192.168.0.1
                            }
                        ]
                    ]
                }
            },
            {
                "type": portmap,
                "capabilities": {
                    "portMappings": true
                }
            },
            {
                "type": firewall
            }
        ]
    }
]
```

### Container operation

```bash
$ isula run -tid --net cni0 --name test busybox sh
3a933b6107114fe684393441ead8addc8994258dab4c982aedb1ea203f0df7d9

$ isula ps
CONTAINER ID    IMAGE   COMMAND CREATED         STATUS          PORTS   NAMES
3a933b610711    busybox "sh"    9 seconds ago   Up 9 seconds            test

$ isula inspect test
...
	"NetworkSettings": {
            "Bridge": "",
            "SandboxID": "",
            "LinkLocalIPv6Address": "",
            "LinkLocalIPv6PrefixLen": 0,
            "Ports": {},
            "CNIPorts": [],
            "SandboxKey": "/var/run/netns/isulacni-e93b9ac71757d204",
            "EndpointID": "",
            "Gateway": "",
            "GlobalIPv6Address": "",
            "GlobalIPv6PrefixLen": 0,
            "IPAddress": "",
            "IPPrefixLen": 0,
            "IPv6Gateway": "",
            "MacAddress": "",
            "Activation": true,
            "Networks": {
                "cni0": {
                    "Links": [],
                    "Alias": [],
                    "NetworkID": "",
                    "EndpointID": "",
                    "Gateway": "192.168.0.1",
                    "IPAddress": "192.168.0.4",
                    "IPPrefixLen": 24,
                    "IPv6Gateway": "",
                    "GlobalIPv6Address": "",
                    "GlobalIPv6PrefixLen": 0,
                    "MacAddress": "d2:74:53:c5:9c:be",
                    "IFName": "eth0",
                    "DriverOpts": {}
                }
            }
        }
...

$ ping 192.168.0.4
PING 192.168.0.4 (192.168.0.4) 56(84) bytes of data.
64 bytes from 192.168.0.4: icmp_seq=1 ttl=64 time=0.080 ms
64 bytes from 192.168.0.4: icmp_seq=2 ttl=64 time=0.038 ms
64 bytes from 192.168.0.4: icmp_seq=3 ttl=64 time=0.038 ms
^C
--- 192.168.0.4 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2084ms
rtt min/avg/max/mdev = 0.038/0.052/0.080/0.019 ms

$ isula rm -f test
3a933b6107114fe684393441ead8addc8994258dab4c982aedb1ea203f0df7d9
```

### Delete network

```bash
$ isula network rm cni0
cni0

$ isula network ls
NAME                 VERSION         PLUGIN
```
