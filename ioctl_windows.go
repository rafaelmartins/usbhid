// Copyright 2022-2024 Rafael G. Martins. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package usbhid

import (
	"syscall"
	"unsafe"
)

const (
	kIOCTL_HID_GET_FEATURE = 0x0b0192
)

var (
	deviceIoControl     = kernel32.NewProc("DeviceIoControl")
	getOverlappedResult = kernel32.NewProc("GetOverlappedResult")
)

func ioctl(fd uintptr, req int, in []byte, out []byte) (int, error) {
	var (
		inb  uintptr
		inl  uintptr
		outb uintptr
		outl uintptr
		rv   uint32
	)
	if in != nil {
		inb = uintptr(unsafe.Pointer(&in[0]))
		inl = uintptr(uint32(len(in)))
	}
	if out != nil {
		outb = uintptr(unsafe.Pointer(&out[0]))
		outl = uintptr(uint32(len(out)))
	}

	ovl := &syscall.Overlapped{}
	_, _, err := deviceIoControl.Call(fd, uintptr(uint32(req)), inb, inl, outb, outl, uintptr(unsafe.Pointer(&rv)), uintptr(unsafe.Pointer(ovl)))
	if err != nil && err.(syscall.Errno) != 0 {
		return 0, err
	}

	_, _, err = getOverlappedResult.Call(fd, uintptr(unsafe.Pointer(ovl)), uintptr(unsafe.Pointer(&rv)), uintptr(int32(1)))
	if err != nil && err.(syscall.Errno) != 0 {
		return 0, err
	}

	return int(rv), nil
}
