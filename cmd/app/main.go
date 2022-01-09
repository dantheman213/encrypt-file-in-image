package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/google/uuid"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var publicKey *rsa.PublicKey

func main() {
	if len(os.Args) - 1 < 4 {
		// error out
	} else {
		actionType := os.Args[1]
		keyPath := os.Args[2]
		inputImageDir := os.Args[3]
		outputImageDir := os.Args[4]

		files := getFiles(inputImageDir)

		if actionType == "encrypt" {
			pub, err := ioutil.ReadFile(keyPath)
			if err != nil {
				panic(err)
			}
			pubPem, _ := pem.Decode(pub)
			if publicKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
				panic(err)
			}

			// load public key
			publicKey = rsa.

			for _, filePath := range files {
				if strings.HasSuffix(strings.ToLower(filePath), ".jpg") {
					// file is a jpg
					newFileName := uuid.New().String() + ".jpg"
					newFilePath := fmt.Sprintf("%s%v%s", outputImageDir, os.PathSeparator, newFileName)
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
	img := image.NewRGBA(image.Rect(0, 0, 220, 220)) // x1,y1,  x2,y2 of background rectangle
	selectedColor := color.RGBA{0, 100, 0, 255}  //  R, G, B, Alpha
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

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,
		dat,
		nil)
	if err != nil {
		panic(err)
	}


}