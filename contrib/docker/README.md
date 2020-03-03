# Dockerization

## Building

To build a docker image of electrum, from the project root run:
```bash
docker build -f contrib/docker/Dockerfile -t electrum:latest .
```

## Running

### daemon

To run the daemon and make a getinfo call, execute:
```bash
docker run -d -p 7777:7777 --name electrum \
    -e WALLET_NAME=wallet_name \
    electrum:latest
docker exec -it -u electrum electrum bash
wallet_name getinfo
```

An alias named as the environment variable `WALLET_NAME` will be created
to easily use `electrum` without adding parameters.

### GUI

To run the GUI, execute:
```bash
xhost +local:docker  # allow docker to make connections to the X server
docker run -d -p 7777:7777 --name electrum \
    -e DAEMON=0 -e WALLET_NAME=wallet_name \
    -e DISPLAY \
    -v /tmp/.X11-unix:/tmp/.X11-unix:ro \
    --device /dev/dri:/dev/dri \
    electrum:latest
xhost -local:docker  # deactivate docker access to the X server
```

## Environment variables

- `DAEMON`: whether to run as a daemon (`1`) or with the GUI (`0`) (default `1`)
- `WALLET_NAME`: name of the electrum wallet to use (no default; mandatory)
- `SERVER_HOST`: when provided, connects to the specified server using
`host:port:protocol` (optional)
- `SERVER_PORT`: server port, only considered if server host is specified
(default `50001`)
- `SERVER_PROTOCOL`: whether to use an insecure connection (`t`) or an
encrypted connection (`s`), only considered if server host is specified
(default `t`)
- `PARAMS`: additional parameters to be appended to `electrum` command
