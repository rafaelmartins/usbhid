// Copyright 2022-2023 Rafael G.Martins. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package usbhid

import (
	"fmt"
	"math"
	"runtime"
	"syscall"
)

var (
	iocWrite    byte
	iocRead     byte
	iocSizeBits byte
	iocDirBits  byte

	iocNrShift   byte
	iocTypeShift byte
	iocSizeShift byte
	iocDirShift  byte
)

func init() {
	switch runtime.GOARCH {
	case "386":
		fallthrough
	case "amd64":
		fallthrough
	case "arm":
		fallthrough
	case "arm64":
		fallthrough
	case "loong64":
		fallthrough
	case "riscv64":
		fallthrough
	case "s390x":
		iocWrite = 1
		iocRead = 2
		iocSizeBits = 14
		iocDirBits = 2

	case "mips":
		fallthrough
	case "mips64":
		fallthrough
	case "mips64le":
		fallthrough
	case "mipsle":
		fallthrough
	case "ppc":
		fallthrough
	case "ppc64":
		fallthrough
	case "ppc64le":
		fallthrough
	case "sparc64":
		iocWrite = 4
		iocRead = 2
		iocSizeBits = 13
		iocDirBits = 3

	default:
		panic("usbhid: unsupported architecture")
	}

	iocNrShift = 0
	iocTypeShift = 8
	iocSizeShift = 16
	iocDirShift = 16 + iocSizeBits
}

func ioc(dir byte, typ byte, nr byte, size uint16) uint32 {
	dir = dir & (byte(math.Pow(2, float64(iocDirBits))) - 1)
	size = size & (uint16(math.Pow(2, float64(iocSizeBits))) - 1)
	return uint32(dir)<<iocDirShift | uint32(typ)<<iocTypeShift | uint32(nr)<<iocNrShift | uint32(size)<<iocSizeShift
}

func ioctl(fd uintptr, request uint, arg uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(request), arg)
	if errno != 0 {
		return fmt.Errorf("usbhid: ioctl: 0x%x: %s", request, errno)
	}
	return nil
}
