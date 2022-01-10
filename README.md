# image-encrypt

Encrypt files and place them into valid placeholder pictures that can be used to hide data locally or upload to cloud providers so they can't read your data.

Placeholder images are legitimate and valid solid color images that can be read with any valid image reader program or service.

## Examples

### Compile

```
git clone ...
cd image-encrypt/
make
```

### Generate key pair

```
openssl genrsa -out /home/user/.ssh/priv.pem 2048
```

### Encrypt

```
bin/image-encrypt encrypt /home/user/.ssh/priv.pem /home/user/Documents/my-pics /home/user/Desktop/encrypted-pics
```

### Decrypt

```
bin/image-encrypt decrypt /home/user/.ssh/priv.pem /home/user/Desktop/encrypted-pics /home/user/Desktop/unecrypted-pics
```