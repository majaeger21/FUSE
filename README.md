# FUSE

### Group Members
- Misaki Tanabe 
- Meyli Jaeger 
- Lukas Chou

### How to run docker file and create mount directory
1. docker build -t mirror-fs .
2. docker rm -f my_persistent_container
3. docker run -it \
  --cap-add SYS_ADMIN \
  --device /dev/fuse \
  --security-opt apparmor:unconfined \
  -v "$PWD":/usr/src/app \
  --name my_persistent_container \
  mirror-fs /bin/bash
4. mkdir -p /tmp/mirror_src /tmp/mirror_mnt
5. ./mirror_fs -o nonempty /tmp/mirror_mnt /tmp/mirror_src

### How to clean up multiple mirror_fs processes and force unmount (clean slate)
1. pkill -9 mirror_fs
2. fusermount -u /tmp/mirror_mnt 2>/dev/null
    - if you get an error run: rm /tmp/mirror_mnt/*
3. rm /tmp/mirror_src/.salt
4. ps aux | grep mirror_fs     --> check if all other processes are killed
5. make clean && make
6. ./mirror_fs -o nonempty /tmp/mirror_mnt /tmp/mirror_src

### Get into running container in another terminal
- docker exec -it my_persistent_container /bin/bash
