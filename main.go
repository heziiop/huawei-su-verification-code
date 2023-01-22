package main

import (
	"crypto/md5"
	"fmt"
	"os"
)


func getSuVerificationCode(challenge string) string {
	var premd5 [8]byte
	for i:=0; i<8; i++ {
		if challenge[i] <= 0x47 {
			premd5[i] = challenge[i]<<1
		} else {
			premd5[i] = challenge[i]>>1
		}
	}
	tmp := md5.Sum(premd5[:])
	prepass := tmp[:]
	var challengePass [8]byte
	for i:=0; i<8; i++ {
		temp2 := uint64(prepass[i]>>1) * uint64(0xB60B60B7)
		temp2 = temp2 >> (5 + 32)
		temp1 := temp2 << 3
		temp1 = temp1 - (temp2<<1)
		temp3 := temp1 << 4
		temp3 = temp3 - temp1
		temp0 := uint64(prepass[i]) - temp3 + 0x21
		temp0 = temp0 & 0xFF
		if temp0 == 0x3F {
			challengePass[i] = 0x3E
		} else {
			challengePass[i] = byte(temp0)
		}
	}
	return string(challengePass[:])
}


func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: huawei-su-verification-code challenge")
		os.Exit(-1)
	}
	if len(os.Args[1]) != 8 {
		fmt.Println("ERROR: Challenge must have 8 chars")
		os.Exit(-1)
	}
	fmt.Println(getSuVerificationCode(os.Args[1]))
}