| Author | 王丰土                                         |
| ------ | ---------------------------------------------- |
| Date   | 2020-05-28                                     |
| Email  | [wangfengtu@huawei.com](wangfengtu@huawei.com) |

# 1.方案目标

registry模块所处的位置如下：

![输入图片说明](https://images.gitee.com/uploads/images/2020/0327/154119_63be70c0_5595781.png "所处位置.png")

Registry模块除了接受Manager模块调用外，还会调用store模块来存放下载下来的镜像和层。

拉取镜像的过程中采用libcurl库来实现和仓库的交互。交互过程中需要用到的一些证书和TLS算法的处理libcurl已实现，使用时配置好路径传入即可。

和仓库交互过程中的认证只需要支持basic认证即可。和仓库的交互过程中的Bear是仓库生成的，客户端只需要保存并在后续操作中携带即可。

需要实现协议Docker Registry HTTP API V2的pull部分,以及OCI distribution spec的pull部分，本文主要描述docker镜像相关下载，OCI镜像的下载请参考协议。下载docker镜像的manifest有两种格式：

- Image Manifest Version 2, Schema 2
- Image Manifest Version 2, Schema 1

# 2.总体设计

Registry内部结构如下：

![输入图片说明](https://images.gitee.com/uploads/images/2020/0327/154200_0d38813a_5595781.png "registry内部结构.png")

1. **Registry apiv2模块**：实现和仓库的交互协议，包括Schema1和Schema2，主要是实现下载manifest、下载config文件、下载layers文件的具体协议，包括实现下载时需要进行的ping操作。
2. **Registry模块**：调用registry apiv2模块下载镜像相关文件，并进行解压/合法性校验后调store的接口注册成镜像，并对Manager模块提供调用接口。
3. **Auth/certs模块**：管理本地的用户名/密码、证书、共私钥等数据。
4. **http/https request模块**：使用libcurl库封装和仓库交互的http/https的交互过程，包括调用auth/certs模块获取/设置相关的密码证书等操作，也包括和仓库交互的auth认证登录操作等协议的实现。

# 3.接口描述

```c
typedef struct {
    /* 登录仓库时使用的用户名 */
    char *username;
    /* 登录仓库时使用的密码 */
    char *password;
}registry_auth;

typedef struct {
    char *image_name;
    char *dest_image_name;
    registry_auth auth;
    bool skip_tls_verify;
    bool insecure_registry;
} registry_pull_options;

typedef struct {
    /* 镜像的仓库地址 */
    char *host;
    registry_auth auth;
    bool skip_tls_verify;
    bool insecure_registry;
} registry_login_options;

int registry_init();
int registry_pull(registry_pull_options *options);
int registry_login(registry_login_options *options);
int registry_logout(char *auth_file_path, char *host);

void free_registry_pull_options(registry_pull_options *options);
void free_registry_login_options(registry_login_options *options);
```

# 4.详细设计

##  **Registry模块** 

Registry模块调用registry apiv2模块下载镜像相关文件，并进行解压/合法性校验后调store的接口注册成镜像，并对Manager模块提供调用接口。

登录操作：直接调用registry apiv2模块提供的接口实现。

登出操作；调用auth/certs模块提供的接口实现。

下面主要描述拉取镜像的过程，交互过程中的协议实现由registry apiv2模块实现：

1、根据传入的镜像名称，组装获取manifest的地址，从镜像仓库请求manifest。

返回的manifests格式(假设返回的是schema1)：

```c
200 OK
Docker-Content-Digest: <digest>
Content-Type: <media type of manifest>

{
   "name": <name>,
   "tag": <tag>,
   "fsLayers": [
      {
         "blobSum": "<digest>"
      },
      ...
    ]
   ],
   "history": <v1 images>,c
   "signature": <JWS>
}
```

格式的详细含义请参考链接：https://docs.docker.com/registry/spec/manifest-v2-1/

如果是schema2，则返回的json格式样例如下：

```c
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
  "manifests": [
    {
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "size": 7143,
      "digest": "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
      "platform": {
        "architecture": "ppc64le",
        "os": "linux",
      }
    },
    {
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "size": 7682,
      "digest": "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
      "platform": {
        "architecture": "amd64",
        "os": "linux",
        "features": [
          "sse4"
        ]
      }
    }
  ]
}
```

格式的详细含义请参考链接：https://docs.docker.com/registry/spec/manifest-v2-2/

Manifests的MediaType我们只支持如下几种：

- application/vnd.docker.distribution.manifest.v2+json
- application/vnd.docker.distribution.manifest.v1+prettyjws  需要能下载使用，暂不解析signature
- application/vnd.docker.distribution.manifest.v1+json
- application/vnd.docker.distribution.manifest.list.v2+json
- application/vnd.oci.image.manifest.v1+json  支持OCI镜像

3、获取到manifest后，解析manifest获取到镜像的配置以及所有层的digest信息。

4、根据获取到的镜像的配置的digest，以及所有层的digest信息，拼接出下载所有这些数据的url地址并进行下载(这里可以并发下载)。

5、下载完成后，需要对镜像的层数据进行解压，解压成tar格式的数据并计算sha256值。然后还需要解析镜像配置信息，获取配置中保存的层的DiffID，并和下载下来的层数据进行sha256对比，校验其正确性。

校验时取配置中的rootfs.diff_ids[$i]值(即第$i层的sha256值)，并取下载后的第$i层解压成tar格式后的数据做sha256的值，两个值需要完全一致。配置中的值如下：

```c
"RootFS": {
            "Type": "layers",
            "Layers": [
                "sha256:e7ebc6e16708285bee3917ae12bf8d172ee0d7684a7830751ab9a1c070e7a125",
                "sha256:f934e33a54a60630267df295a5c232ceb15b2938ebb0476364192b1537449093",
                "sha256:bf6751561805be7d07d66f6acb2a33e99cf0cc0a20f5fd5d94a3c7f8ae55c2a1",
                "sha256:943edb549a8300092a714190dfe633341c0ffb483784c4fdfe884b9019f6a0b4",
                "sha256:c1bd37d01c89de343d68867518b1155cb297d8e03942066ecb44ae8f46b608a3",
                "sha256:cf612f747e0fbcc1674f88712b7bc1cd8b91cf0be8f9e9771235169f139d507c",
                "sha256:14dd68f4c7e23d6a2363c2320747ab88986dfd43ba0489d139eeac3ac75323b2"
            ]
        }
```

6、调用store模块将下载下来的层数据和配置注册生成镜像，并对镜像添加对应的名称。

##  **Registry apiv2模块** 

该模块负责实现和镜像仓库的交互的协议(Docker Registry HTTP API V2)中和拉取镜像相关的那部分协议，其中manifest的形式包括Image Manifest Version 2, Schema 1和Schema 2。

这里只对协议做简要说明，细节请参考下面链接中的详细说明：

https://docs.docker.com/registry/spec/api/
https://docs.docker.com/registry/spec/manifest-v2-1/
https://docs.docker.com/registry/spec/manifest-v2-2/

以及基于上述协议的OCI distribution spec：

https://github.com/opencontainers/distribution-spec/blob/master/spec.md

和镜像仓库的交互过程，会先尝试使用https协议，如果失败则会继续尝试使用http协议交互(该行为可以配置)。
交互过程有一些通用的配置/交互过程，如下：

1、ping仓库。一次登录/下载的过程，需要并且只需要ping一次仓库。Ping的主要目的是获取仓库返回的相关信息。
ping请求格式：

```http
GET /v2/
Host: <registry host>
Authorization: <scheme> <token>
```

成功：
`200 OK`
不支持V2协议：
`404 Not Found`
未认证：

```http
401 Unauthorized
WWW-Authenticate: <scheme> realm="<realm>", ..."
Content-Length: <length>
Content-Type: application/json; charset=utf-8

{
	"errors:" [
	    {
            "code": <error code>,
            "message": "<error message>",
            "detail": ...
        },
        ...
    ]
}
```

Ping返回的头部信息必须包含字段：
`Docker-Distribution-API-Version：registry/2.0`

如果返回的是401未认证，则必须包含字段WWW-Authenticate表示我们该去哪里进行认证。

2、进行认证。先从返回的401未认证的http头部字段WWW-Authenticate中获取相关的认证方式信息。认证方式只支持Basic方式和Bearer方式。注意可能会携带多个WWW-Authenticate字段，表示同时支持多种认证方式，需要对每个字段都解析处理。

Basic方式，后续的所有的请求都需要携带如下头部信息：

`Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l`

其中QWxhZGRpbjpPcGVuU2VzYW1l是用户名密码按照username:passord的格式进行base64编码后的字符串。

Bearer token方式，后续的所有的请求都需要携带如下头部信息：

`Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IkJWM0Q6MkFWWjpVQjVaOktJQVA6SU5QTDo1RU42Ok40SjQ6Nk1XTzpEUktFOkJWUUs6M0ZKTDpQT1RMIn0.eyJpc3MiOiJhdXRoLmRvY2tlci5jb20iLCJzdWIiOiJCQ0NZOk9VNlo6UUVKNTpXTjJDOjJBVkM6WTdZRDpBM0xZOjQ1VVc6NE9HRDpLQUxMOkNOSjU6NUlVTCIsImF1ZCI6InJlZ2lzdHJ5LmRvY2tlci5jb20iLCJleHAiOjE0MTUzODczMTUsIm5iZiI6MTQxNTM4NzAxNSwiaWF0IjoxNDE1Mzg3MDE1LCJqdGkiOiJ0WUpDTzFjNmNueXk3a0FuMGM3cktQZ2JWMUgxYkZ3cyIsInNjb3BlIjoiamxoYXduOnJlcG9zaXRvcnk6c2FtYWxiYS9teS1hcHA6cHVzaCxwdWxsIGpsaGF3bjpuYW1lc3BhY2U6c2FtYWxiYTpwdWxsIn0.Y3zZSwaZPqy4y9oRBVRImZyv3m_S9XDHF1tWwN7mL52C_IiA73SJkWVNsvNqpJIn5h7A2F8biv_S2ppQ1lgkbw`

其中一长串token是从认证服务器获取的，

协议的详细实现见链接：https://docs.docker.com/registry/spec/auth/token/

这里只做简单描述。



![输入图片说明](https://images.gitee.com/uploads/images/2020/0327/161248_05fd7c37_5595781.png "auth.png")

登录验证的过程如上图。每步含义如下：

1.客户端尝试从仓库pull镜像，即发送了pull镜像的请求，或其它操作。

2.如果仓库需要登录，则会返回401 Unauthorized未认证，返回的消息中携带了WWW-Authenticate 字段，如下所示：

```txt
www-Authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:samalba/my-app:pull,push"
```

各个字段含义如下：

  - Bearer realm：认证服务器地址。

  - service：镜像仓库地址。

  - scope：操作的范围，即需要哪些权限。

3.客户端根据前面返回的信息，组装URL请求向认证服务器请求bear token用于后续的交互。组装后的URL如下所示：

```url
https://auth.docker.io/token?service=registry.docker.io&scope=repository:samalba/my-app:pull,push
```

4.认证服务器返回token以及过期时间等信息

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IlBZWU86VEVXVTpWN0pIOjI2SlY6QVFUWjpMSkMzOlNYVko6WEdIQTozNEYyOjJMQVE6WlJNSzpaN1E2In0.eyJpc3MiOiJhdXRoLmRvY2tlci5jb20iLCJzdWIiOiJqbGhhd24iLCJhdWQiOiJyZWdpc3RyeS5kb2NrZXIuY29tIiwiZXhwIjoxNDE1Mzg3MzE1LCJuYmYiOjE0MTUzODcwMTUsImlhdCI6MTQxNTM4NzAxNSwianRpIjoidFlKQ08xYzZjbnl5N2tBbjBjN3JLUGdiVjFIMWJGd3MiLCJhY2Nlc3MiOlt7InR5cGUiOiJyZXBvc2l0b3J5IiwibmFtZSI6InNhbWFsYmEvbXktYXBwIiwiYWN0aW9ucyI6WyJwdXNoIl19XX0.QhflHPfbd6eVF4lM9bwYpFZIV0PfikbyXuLx959ykRTBpe3CYnzs6YBK8FToVb5R47920PVLrh8zuLzdCr9t3w", "expires_in": 3600,"issued_at": "2009-11-10T23:00:00Z"}
```

5.重新请求pull操作，这次在请求时在Authorization字段里携带上Bearer token作为认证成功的标识：

```txt
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IkJWM0Q6MkFWWjpVQjVaOktJQVA6SU5QTDo1RU42Ok40SjQ6Nk1XTzpEUktFOkJWUUs6M0ZKTDpQT1RMIn0.eyJpc3MiOiJhdXRoLmRvY2tlci5jb20iLCJzdWIiOiJCQ0NZOk9VNlo6UUVKNTpXTjJDOjJBVkM6WTdZRDpBM0xZOjQ1VVc6NE9HRDpLQUxMOkNOSjU6NUlVTCIsImF1ZCI6InJlZ2lzdHJ5LmRvY2tlci5jb20iLCJleHAiOjE0MTUzODczMTUsIm5iZiI6MTQxNTM4NzAxNSwiaWF0IjoxNDE1Mzg3MDE1LCJqdGkiOiJ0WUpDTzFjNmNueXk3a0FuMGM3cktQZ2JWMUgxYkZ3cyIsInNjb3BlIjoiamxoYXduOnJlcG9zaXRvcnk6c2FtYWxiYS9teS1hcHA6cHVzaCxwdWxsIGpsaGF3bjpuYW1lc3BhY2U6c2FtYWxiYTpwdWxsIn0.Y3zZSwaZPqy4y9oRBVRImZyv3m_S9XDHF1tWwN7mL52C_IiA73SJkWVNsvNqpJIn5h7A2F8biv_S2ppQ1lgkbw
```

6.服务器端校验Bearer token并允许pull操作。



下面介绍下载manifest/config/layers数据的过程：

1、根据传入的镜像名称，组装获取manifest的地址，从镜像仓库请求manifest。

请求manifests：

```http
GET /v2/<name>/manifests/<reference>
Host: <registry host>
Authorization: <scheme> <token>
```

这里的name是镜像名，不包括tag，而reference则是指tag

例如，拉取镜像docker.io/library/node:latest，则上述格式为：

GET /v2/library/node/manifests/latest

返回的头部信息中的Content-Type字段会携带具体的manifest的类型（见前面5.1.2节的描述）。body内容则是对应的json字符串。

2、镜像的配置和层，对于仓库来说都是blob，只要根据manifest里面解析出来的digeset值，就能获取到blob数据。Digest的值就是配置/层的数据的sha256的值(未解压前)，同时也是下载这些blob数据的url的一部分：

获取层/digest的请求(这里可以并发请求)：

```http
GET /v2/<name>/blobs/<digest>
Host: <registry host>
Authorization: <scheme> <token>
```

获取成功(失败返回的格式请参考协议)：

```http
200 OK
Content-Length: <length>
Docker-Content-Digest: <digest>
Content-Type: application/octet-stream

<blob binary data>
```

##  **auth/certs模块** 

该模块分成两部分，auth负责管理login登录的用户名密码，提供读取和设置的接口。certs负责管理和仓库交互时https请求用到的证书和私钥，提供读取的接口。

1) 登录仓库时使用的证书放在/root/.isulad/auths.json文件中保存，如下：

```shell
# pwd
/root/.isulad
# ls
aeskey  auths.json  auths.json.lock
# cat auths.json
{
	"auths": {
		"dockerhub.test.com": {
			"auth": "nS6GX1wnf4WGe6+O+nS6Py6CVzPPIQJBOksaFSfFAy9LRUijubMIgZhtfrA="
		}
	}
}
```

auths.json中的auths中保存了各个仓库以及对应的用户名密码。用户名密码加密规则为将用户名密码组成  $USERNAME:$PASSWORD 字符串后，然后使用AES加密，然后再使用base64对加密后的数据进行编码，作为json文件的auth字段存储。

2) HTTPS请求用到的证书，放在/etc/isulad/certs.d/$registry目录下：

```shell
# pwd
/etc/isulad/certs.d/dockerhub.test.com
# ls
ca.crt  tls.cert  tls.key
```

##  **http/https request模块** 

和镜像仓库交互需要调用libcurl库来实现registry API V2的客户端协议。

协议的处理已在前面有描述，这里主要描述http/https请求的封装。

libcurl提供了实现请求的原子命令，该模块需要基于libcurl提供的原子接口封装http_request接口。需要封装多个接口，以便能方便地处理各种请求。主要封装三个函数：

1、通过内存返回数据和仓库交互，用于进行ping等数据量较小的操作。

2、通过内存返回数据和认证服务器交互，用于获取token。该函数在模块内部使用，不对外提供接口。

3、通过文件返回数据的。用于获取比较大的数据量的请求，例如获取blob数据和获取manifests数据。

除了URL之外，还需要支持配置如下参数：

1、用户名密码等认证信息

2、返回消息头还是返回body还是都返回

3、TLS相关信息

4、自定义消息头信息

