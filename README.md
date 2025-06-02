# FUSE

### Group Members
- Misaki Tanabe 
- Meyli Jaeger 
- Lukas Chou

### How to run docker file
docker build -t mirror-fs .

docker rm -f my_persistent_container

docker run -it \
  --cap-add SYS_ADMIN \
  --device /dev/fuse \
  --security-opt apparmor:unconfined \
  -v "$PWD":/usr/src/app \
  --name my_persistent_container \
  mirror-fs /bin/bash

mkdir -p /tmp/mirror_src /tmp/mirror_mnt

./mirror_fs -o nonempty /tmp/mirror_mnt /tmp/mirror_src

Get into running container in another terminal:
- docker exec -it my_persistent_container /bin/bash
