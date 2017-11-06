Docker support
==============

Prerequisites and caveats
-------------------------
* Requires [`docker`](https://docs.docker.com/engine/installation/) 
  and [`docker-compose`](https://docs.docker.com/compose/install/) be installed/configured
* Downloads and agent logs persistently stored in volume mount at `downloads/`
* Database (`data/empire.db`) and default generated certificate (`data/empire.pem`) 
  currently not persisted outside of the container because of limitations in dir structure. This
  means that database state will be lost if the docker containers are destroyed or recreated 
  (i.e. `docker-compose down`).
* All commands should be run from `docker/` subdirectory


A note about networking
---------------------
The default `docker-compose.yml` is configured for `host` networking mode which 
will allow all empire listener ports to automatically be exposed on the host system.
This mode [isn't currently supported on mac](https://github.com/docker/for-mac/issues/1031)
so the default `bridge` network mode will need to be used with 
[explicit port forwards (see below)](#use-port-forwards-for-listeners).

Start container
---------------
```console
$ docker-compose up -d
```

Attach to container
-------------------
Note that this is `docker` and not `docker-compose`
```console
$ docker attach empire
(Empire) >
```

Detach from container
---------------------
Use the `[ctrl-p][ctrl-q]` hotkey sequence to break out of the Empire shell and drop back the system shell.
```console
(Empire) >[ctrl-p][ctrl-q]
$
```

Destroy container
-----------------
```console
$ docker-compose down
```

Use port forward(s) for listeners
---------------------------------
This is only required using `bridge` network mode and not `host` network mode (i.e. on Mac). Rename `docker-compose.portfwd.yml` to `docker-compose.override.yml`
and modify `ports:` entry as appropriate with desired port forwards.
```console
$ cp docker-compose.portfwd.yml docker-compose.override.yml
$ vim docker-compose.override.yml
$ docker-compose up -d
Recreating empire ...
Recreating empire ... done
```