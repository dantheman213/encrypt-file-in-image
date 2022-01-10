package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/google/uuid"
	"hash"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	mathRand "math/rand"
)

var privateKey *rsa.PrivateKey
var baseDirName string
var pathMarkerBytes []byte = []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCB, 0xEE }
var jpegSuffixBytes []byte = []byte{0xFF, 0xD9}

func main() {
	if len(os.Args) - 1 < 4 {
		// error out
	} else {
		actionType := os.Args[1]
		keyPath := os.Args[2]
		inputImageDir := os.Args[3]
		outputImageDir := os.Args[4]

		fmt.Printf("loading private key at %s...\n", keyPath)
		loadPrivateKey(keyPath)

		fmt.Println("getting list of files in input directory")
		files := getFiles(inputImageDir)

		if actionType == "encrypt" {
			pathParts := strings.Split(inputImageDir, string(os.PathSeparator))
			baseDirName = pathParts[len(pathParts) - 1]
			fmt.Printf("base path set as %s\n", baseDirName)

			for _, filePath := range files {
				if strings.HasSuffix(strings.ToLower(filePath), ".jpg") {
					// file is a jpg
					newFileName := uuid.New().String() + ".jpg"
					newFilePath := fmt.Sprintf("%s%c%s", outputImageDir, os.PathSeparator, newFileName)

					fmt.Printf("encrypting %s to %s\n", filePath, newFilePath)

					createPlaceholderJpeg(newFilePath)
					addEncryptedPayloadToImage(newFilePath, filePath)
				}
			}
		} else if actionType == "decrypt" {

		} else {
			// error
		}
	}
}

func getFiles(dirPath string) []string {
	var files []string

	err := filepath.Walk(dirPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			//fmt.Println(path, info.Size())
			files = append(files, path)
			return nil
		})
	if err != nil {
		log.Println(err)
	}

	return files
}

func createPlaceholderJpeg(outputFilePath string) {
	img := image.NewRGBA(image.Rect(0, 0, getRandomNum(1000, 5000), getRandomNum(1000, 5000))) // x1,y1,  x2,y2 of background rectangle

	selectedColor := color.RGBA{uint8(getRandomNum(0, 255)), uint8(getRandomNum(0, 255)), uint8(getRandomNum(0, 255)), 255} //  R, G, B, Alpha
	draw.Draw(img, img.Bounds(), &image.Uniform{selectedColor}, image.ZP, draw.Src)

	f, err := os.Create(outputFilePath)     // ... now lets save imag
	if err != nil {
		panic(err)
	}
	defer f.Close()

	err = jpeg.Encode(f, img, nil)
	if err != nil {
		panic(err)
	}
}

func addEncryptedPayloadToImage(containerImagePath string, sourceImagePath string) {
	dat, err := ioutil.ReadFile(sourceImagePath)

	encryptedDataBytes, err := encryptOAEP(
		sha256.New(),
		rand.Reader,
		&privateKey.PublicKey,
		dat,
		nil)
	if err != nil {
		panic(err)
	}

	relativeFilePath := getRelativePathFromFilePath(sourceImagePath)
	fmt.Printf("embedding relative path %s\n", relativeFilePath)
	encryptedPathBytes, err := encryptOAEP(
		sha256.New(),
		rand.Reader,
		&privateKey.PublicKey,
		[]byte(relativeFilePath),
		nil)
	if err != nil {
		panic(err)
	}

	encryptedFinalPayload := append(encryptedDataBytes, pathMarkerBytes...)
	encryptedFinalPayload = append(encryptedFinalPayload, encryptedPathBytes...)

	// append encrypted binary to container file
	f, err := os.OpenFile(containerImagePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if _, err = f.Write(encryptedFinalPayload); err != nil {
		panic(err)
	}
}

func loadPrivateKey(privateFileKeyPath string) {
	pemData, err := ioutil.ReadFile(privateFileKeyPath)
	if err != nil {
		log.Fatalf("read key file: %s", err)
	}

	// Extract the PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		log.Fatalf("bad key data: %s", "not PEM-encoded")
	}
	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		log.Fatalf("unknown key type %q, want %q", got, want)
	}

	// Decode the RSA private key
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("bad private key: %s", err)
	}

	privateKey = priv
}

func encryptOAEP(hash hash.Hash, random io.Reader, public *rsa.PublicKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := public.Size() - 2*hash.Size() - 2
	var encryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		encryptedBlockBytes, err := rsa.EncryptOAEP(hash, random, public, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}

	return encryptedBytes, nil
}

func decryptOAEP(hash hash.Hash, random io.Reader, private *rsa.PrivateKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := private.PublicKey.Size()
	var decryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedBlockBytes, err := rsa.DecryptOAEP(hash, random, private, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}

	return decryptedBytes, nil
}

func getRelativePathFromFilePath(filePath string) string {
	relativePathPosStart := strings.Index(filePath, baseDirName + string(os.PathSeparator))
	return filePath[relativePathPosStart:len(filePath)]
}

func getRandomNum(min, max int) int {
	return mathRand.Intn(max - min) + min
}
