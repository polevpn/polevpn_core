package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"runtime/debug"
	"strconv"
)

func PanicHandler() {
	if err := recover(); err != nil {
		plog.Error("Panic Exception:", err)
		plog.Error(string(debug.Stack()))
	}
}

func PanicHandlerExit() {
	if err := recover(); err != nil {
		plog.Error("Panic Exception:", err)
		plog.Error(string(debug.Stack()))
		plog.Error("************Program Exit************")
		os.Exit(0)
	}
}

func GetRemoteIPByEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)

	if err != nil {
		return "", err
	}

	addr, err := net.ResolveIPAddr("ip", u.Hostname())

	if err != nil {
		return "", err
	}

	return addr.String(), nil
}

func GetHostByEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)

	if err != nil {
		return "", err
	}

	return u.Hostname(), nil
}

func ReadPacket(conn io.Reader) ([]byte, error) {

	prefetch := make([]byte, 2)

	_, err := io.ReadFull(conn, prefetch)

	if err != nil {
		return nil, err
	}

	len := binary.BigEndian.Uint16(prefetch)

	if len < POLE_PACKET_HEADER_LEN {
		return nil, errors.New("invalid pkt len=" + strconv.Itoa(int(len)))
	}

	pkt := make([]byte, len)
	copy(pkt, prefetch)

	_, err = io.ReadFull(conn, pkt[2:])

	if err != nil {
		return nil, err
	}

	return pkt, nil
}

var AesKey = []byte{0x15, 0xfc, 0xf2, 0x66, 0x78, 0x10, 0x5a, 0x34, 0xef, 0x5e, 0xac, 0xcb, 0x6f, 0x78, 0x53, 0xdc}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//AES加密
func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//AES解密
func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}
