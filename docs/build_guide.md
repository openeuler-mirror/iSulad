# Build iSulad from source

If you intend to contribute on iSulad. Thanks for your effort. Every contribution is very appreciated for us.

## Build iSulad based on openEuler distribution

If you use the openEuler distribution, you can easily install various dependent packages via yum.

### Install Dependencies

```sh
$ sudo yum install -y cmake gcc-c++ systemd-devel yajl-devel libcurl libcurl-devel clibcni clibcni-devel protobuf-devel grpc-devel grpc-plugins http-parser-devel libwebsockets-devel libevhtp-devel libevent-devel lcr lxc-devel
```

### Build steps:

Run the cmds under the iSulad source directory
```sh
$ sudo mkdir build
$ sudo cd build
$ sudo cmake ..
$ sudo make
$ sudo make install
```

## Trial iSulad Via Docker container

You can try to use iSulad via Docker container. The following steps guide you how to create a Docker container which can run iSulad inside.

#### Build image

You can build `iSulad` via a Linux-based Docker container. You can build an image from the`Dockerfile` in the source directory. From the iSulad source root directory you can run the following command to make your image.

```sh
$ sudo docker build --build-arg http_proxy=YOUR_HTTP_PROXY_IF_NEED
		--build-arg https_proxy=YOUR_HTTPS_PROXY_IF_NEED \
		-t YOUR_IMAGE_NAME -f ./Dockerfile .
```

#### Prepare root directory for the iSulad

Let's prepare a root directory on host, and we will mount this directory into the container. This  directory be used by `iSulad` in container. 

```sh
$ sudo mkdir -p /var/lib/isulad
```

#### Build iSulad in container

Let's suppose that you built an image called `isulad:dev`.

Then from the iSulad source root directory you can run the following command:

```sh
$ sudo docker run -tid --name YOUR_CONTAINER_NAME -v /var/lib/isulad:/var/lib/isulad -v `pwd`:/src/isulad --privileged isulad:dev
```

Let's suppose that you run an container named `iSulad_build`. Then you can use the following commands to build iSulad in your container `iSulad_build`:

```bash
// enter the container
$ sudo docker exec -it iSulad_build bash
// Now you enter the container, so build iSulad in the container by following commands
# cd /src/isulad
# mkdir build
# cd build
# cmake ..
# make
# make install
```

Now You can use direct command to start `iSulad` server in the container：

```sh
$ sudo isulad # run the server with default socket name and default log level and images manage function
```
