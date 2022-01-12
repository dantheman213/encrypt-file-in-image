package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/google/uuid"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"io"
	"io/ioutil"
	"log"
	mathRand "math/rand"
	"os"
	"path/filepath"
	"strings"
)

var jpegSuffixBytes []byte = []byte{0xFF, 0xD9} // end of container file marker
var pathMarkerBytes []byte = []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCB, 0xEE } // separates payload from stored path

var key []byte
var baseDirName string
var outputFileDir string

func main() {
	if len(os.Args) - 1 < 4 {
		log.Fatalln("not enough arguments")
	} else {
		actionType := os.Args[1]
		keyPath := os.Args[2]
		inputFileDir := os.Args[3]
		outputFileDir = os.Args[4]

		fmt.Printf("loading key at %s...\n", keyPath)
		err := loadAESKey(keyPath)
		if err != nil {
			panic(err)
		}

		fmt.Println("getting list of files in input directory")
		files := getFiles(inputFileDir)

		if actionType == "encrypt" {
			pathParts := strings.Split(inputFileDir, string(os.PathSeparator))
			baseDirName = pathParts[len(pathParts) - 1]
			fmt.Printf("base path set as %s\n", baseDirName)

			for _, filePath := range files {
				newFileName := uuid.New().String() + ".jpg"
				newFilePath := fmt.Sprintf("%s%c%s", outputFileDir, os.PathSeparator, newFileName)

				fmt.Printf("encrypting %s to %s\n", filePath, newFilePath)

				createPlaceholderJpeg(newFilePath)
				addEncryptedPayloadToImage(newFilePath, filePath)
			}
		} else if actionType == "decrypt" {
			for _, filePath := range files {
				if strings.HasSuffix(strings.ToLower(filePath), ".jpg") {
					// found jpg file, assume it's an encrypted container
					decryptPayloadFromImageContainer(filePath)
				}
			}
		} else {
			// error
			log.Fatalln("unknown action command")
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
			if !info.IsDir() {
				files = append(files, path)
			}
			//fmt.Println(path, info.Size())
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
	if err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	encryptedPayload := aesgcm.Seal(nil, nonce, dat, nil)

	relativeFilePath := getRelativePathFromFilePath(sourceImagePath)
	fmt.Printf("embedding relative path %s\n", relativeFilePath)

	encryptedPath := aesgcm.Seal(nil, nonce, []byte(relativeFilePath), nil)

	encryptedFinalPayload := append(encryptedPayload, pathMarkerBytes...)
	encryptedFinalPayload = append(encryptedFinalPayload, encryptedPath...)
	encryptedFinalPayload = append(encryptedFinalPayload, nonce...)

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

func getRelativePathFromFilePath(filePath string) string {
	relativePathPosStart := strings.Index(filePath, baseDirName + string(os.PathSeparator))
	return filePath[relativePathPosStart:len(filePath)]
}

func getRandomNum(min, max int) int {
	return mathRand.Intn(max - min) + min
}

func decryptPayloadFromImageContainer(filePath string) {
	dat, err := ioutil.ReadFile(filePath)
	if err != nil {
		panic(err)
	}

	fmt.Printf("attempting to decrypt %s... ", filePath)

	jpegEndOffset := bytes.Index(dat, jpegSuffixBytes)
	pathMarkerOffset := bytes.Index(dat, pathMarkerBytes)
	if pathMarkerOffset > 1 && jpegEndOffset > 1 {
		fmt.Printf("found encrypted container...!\n")

		payloadDat := dat[jpegEndOffset + 2: pathMarkerOffset]
		relativePathDat := dat[pathMarkerOffset + 8:len(dat)-12]
		nonceDat := dat[len(dat)-12:len(dat)]

		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}

		decryptedPayload, err := aesgcm.Open(nil, nonceDat, payloadDat, nil)
		if err != nil {
			panic(err)
		}

		decryptedRelativePath, err := aesgcm.Open(nil, nonceDat, relativePathDat, nil)
		if err != nil {
			panic(err)
		}

		path := normalizePathSeparator(fmt.Sprintf("%s%c%s", outputFileDir, os.PathSeparator, decryptedRelativePath))
		fmt.Printf("decrypting payload to %s\n", path)

		if err := createDirsForFile(path); err != nil {
			panic(err)
		}

		if err := ioutil.WriteFile(path, decryptedPayload, 0775); err != nil {
			panic(err)
		}
	} else {
		fmt.Printf("didn't encrypted payload... skipping...\n")
	}
}

func createDirsForFile(filePath string) error {
	dir := filepath.Dir(filePath)
	if !dirExists(dir) {
		return os.MkdirAll(dir, 0770)
	}

	return nil
}

func dirExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}

	return false
}

// normalize file paths from other operating systems if needed
func normalizePathSeparator(filePath string) string {
	currentSep := string(os.PathSeparator)
	otherSep := "\\"

	if currentSep == "\\" {
		otherSep = "/"
	}

	if strings.Contains(filePath, otherSep) {
		return strings.ReplaceAll(filePath, otherSep, currentSep)
	}

	return filePath
}

func loadAESKey(keyFilePath string) error {
	var err error
	key, err = ioutil.ReadFile(keyFilePath)

	return err
}