## To Improve

### callbacks and its parameter
有很多这样的函数， 指定callbacks的时候同时还要指定callbacks的参数，这种写法太令人费解了， 能否用宏来简化
```shell
nghttp2_session_server_new(&session_data->session, callbacks, session_data);
```