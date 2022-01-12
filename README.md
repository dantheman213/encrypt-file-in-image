# encrypt-file-in-image

Encrypt files and place them into valid placeholder pictures that can be used to hide data locally or upload to cloud providers so they can't read your data.

Placeholder images are legitimate and valid solid color images that can be read with any valid image reader program or service.

## Examples

### Compile

```
git clone ...
cd encrypt-file-in-image/
make
```

### Generate key pair

```
head -c 32 /dev/urandom > file.key
```

### Encrypt

```
bin/encrypt-file-in-image encrypt /home/user/Documents/file.key /home/user/Documents/my-pics /home/user/Desktop/encrypted-pics
```

### Decrypt

```
bin/encrypt-file-in-image decrypt /home/user/Documents/file.key /home/user/Desktop/encrypted-pics /home/user/Desktop/unecrypted-pics
```