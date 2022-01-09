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

var privateKey *rsa.PrivateKey

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
			for _, filePath := range files {
				if strings.HasSuffix(strings.ToLower(filePath), ".jpg") {
					// file is a jpg
					fmt.Printf("encrypting %s\n", filePath)

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
		&privateKey.PublicKey,
		dat,
		nil)
	if err != nil {
		panic(err)
	}

	// append encrypted binary to container file
	f, err := os.OpenFile(containerImagePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if _, err = 	f.Write(encryptedBytes); err != nil {
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
