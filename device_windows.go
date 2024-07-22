// Copyright 2022-2024 Rafael G. Martins. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package usbhid

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"strings"
	"syscall"
	"unsafe"
)

type deviceExtra struct {
	file  *os.File
	flock *os.File
}

const (
	kLOCKFILE_FAIL_IMMEDIATELY = 0x01
	kLOCKFILE_EXCLUSIVE_LOCK   = 0x02
	kERROR_LOCK_VIOLATION      = 0x21
)

var (
	kernel32   = syscall.NewLazyDLL("kernel32.dll")
	lockFileEx = kernel32.NewProc("LockFileEx")
)

const (
	sDIGCF_PRESENT         = 0x02
	sDIGCF_DEVICEINTERFACE = 0x10
)

const (
	hHIDP_STATUS_SUCCESS uintptr = 0x00110000
)

var (
	setupapi                         = syscall.NewLazyDLL("setupapi.dll")
	setupDiDestroyDeviceInfoList     = setupapi.NewProc("SetupDiDestroyDeviceInfoList")
	setupDiEnumDeviceInterfaces      = setupapi.NewProc("SetupDiEnumDeviceInterfaces")
	setupDiGetClassDevsA             = setupapi.NewProc("SetupDiGetClassDevsA")
	setupDiGetDeviceInterfaceDetailA = setupapi.NewProc("SetupDiGetDeviceInterfaceDetailA")
)

var (
	hid                        = syscall.NewLazyDLL("hid.dll")
	hidD_FreePreparsedData     = hid.NewProc("HidD_FreePreparsedData")
	hidD_GetAttributes         = hid.NewProc("HidD_GetAttributes")
	hidD_GetHidGuid            = hid.NewProc("HidD_GetHidGuid")
	hidD_GetManufacturerString = hid.NewProc("HidD_GetManufacturerString")
	hidD_GetPreparsedData      = hid.NewProc("HidD_GetPreparsedData")
	hidD_GetProductString      = hid.NewProc("HidD_GetProductString")
	hidD_GetSerialNumberString = hid.NewProc("HidD_GetSerialNumberString")
	hidD_SetFeature            = hid.NewProc("HidD_SetFeature")
	hidP_GetCaps               = hid.NewProc("HidP_GetCaps")
)

type gGUID struct {
	data1 uint32
	data2 uint16
	data3 uint16
	data4 [8]uint8
}

type sSP_DEVICE_INTERFACE_DATA struct {
	cbSize   uint32
	guid     gGUID
	flags    uint32
	reserved uintptr
}

type sSP_DEVICE_INTERFACE_DETAIL_DATA_A struct {
	cbSize     uint32
	devicePath [1]byte
}

type hHIDD_ATTRIBUTES struct {
	size      uint32
	vendorID  uint16
	productID uint16
	version   uint16
}

type hHIDP_CAPS struct {
	usage                     uint16
	usagePage                 uint16
	inputReportByteLength     uint16
	outputReportByteLength    uint16
	featureReportByteLength   uint16
	reserved                  [17]uint16
	numberLinkCollectionNodes uint16
	numberInputButtonCaps     uint16
	numberInputValueCaps      uint16
	numberInputDataIndices    uint16
	numberOutputButtonCaps    uint16
	numberOutputValueCaps     uint16
	numberOutputDataIndices   uint16
	numberFeatureButtonCaps   uint16
	numberFeatureValueCaps    uint16
	numberFeatureDataIndices  uint16
}

func enumerate() ([]*Device, error) {
	guid := gGUID{}
	if _, _, err := hidD_GetHidGuid.Call(uintptr(unsafe.Pointer(&guid))); err != nil && err.(syscall.Errno) != 0 {
		return nil, err
	}

	devInfo, _, err := setupDiGetClassDevsA.Call(uintptr(unsafe.Pointer(&guid)), 0, 0, uintptr(sDIGCF_PRESENT|sDIGCF_DEVICEINTERFACE))
	if err != nil && err.(syscall.Errno) != 0 {
		return nil, err
	}
	defer setupDiDestroyDeviceInfoList.Call(devInfo)

	idx := uint32(0)
	rv := []*Device{}

	for {
		itf := sSP_DEVICE_INTERFACE_DATA{}
		itf.cbSize = uint32(unsafe.Sizeof(itf))

		b, _, err := setupDiEnumDeviceInterfaces.Call(devInfo, 0, uintptr(unsafe.Pointer(&guid)), uintptr(idx), uintptr(unsafe.Pointer(&itf)))
		idx++
		if b == 0 {
			break
		}
		if err != nil && err.(syscall.Errno) != 0 {
			continue
		}

		reqSize := uint32(0)
		_, _, err = setupDiGetDeviceInterfaceDetailA.Call(devInfo, uintptr(unsafe.Pointer(&itf)), 0, uintptr(uint32(0)), uintptr(unsafe.Pointer(&reqSize)), 0)
		if err != nil && err.(syscall.Errno) != syscall.ERROR_INSUFFICIENT_BUFFER {
			continue
		}

		detailBuf := make([]byte, reqSize)
		detail := (*sSP_DEVICE_INTERFACE_DETAIL_DATA_A)(unsafe.Pointer(&detailBuf[0]))
		detail.cbSize = uint32(unsafe.Sizeof(sSP_DEVICE_INTERFACE_DETAIL_DATA_A{}))

		_, _, err = setupDiGetDeviceInterfaceDetailA.Call(devInfo, uintptr(unsafe.Pointer(&itf)), uintptr(unsafe.Pointer(detail)), uintptr(reqSize), 0, 0)
		if err != nil && err.(syscall.Errno) != 0 {
			continue
		}

		path := strings.TrimSpace(string(detailBuf[unsafe.Offsetof(detail.devicePath) : len(detailBuf)-1]))

		d := func() *Device {
			f, err := os.OpenFile(path, os.O_RDWR, 0755)
			if err != nil {
				return nil
			}
			defer f.Close()

			rv := &Device{
				path: path,
			}

			attr := hHIDD_ATTRIBUTES{}
			_, _, err = hidD_GetAttributes.Call(f.Fd(), uintptr(unsafe.Pointer(&attr)))
			if err != nil && err.(syscall.Errno) != 0 {
				return nil
			}
			rv.vendorId = attr.vendorID
			rv.productId = attr.productID
			rv.version = attr.version

			buf := make([]uint16, 4092/2)

			_, _, err = hidD_GetManufacturerString.Call(f.Fd(), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
			if err != nil && err.(syscall.Errno) == 0 {
				rv.manufacturer = syscall.UTF16ToString(buf)
			}

			_, _, err = hidD_GetProductString.Call(f.Fd(), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
			if err != nil && err.(syscall.Errno) == 0 {
				rv.product = syscall.UTF16ToString(buf)
			}

			_, _, err = hidD_GetSerialNumberString.Call(f.Fd(), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
			if err != nil && err.(syscall.Errno) == 0 {
				rv.serialNumber = syscall.UTF16ToString(buf)
			}

			var preparsed uintptr
			b, _, err := hidD_GetPreparsedData.Call(f.Fd(), uintptr(unsafe.Pointer(&preparsed)))
			if err != nil && err.(syscall.Errno) != 0 {
				return nil
			}
			if b == 0 {
				return nil
			}
			defer hidD_FreePreparsedData.Call(preparsed)

			var caps hHIDP_CAPS
			status, _, err := hidP_GetCaps.Call(preparsed, uintptr(unsafe.Pointer(&caps)))
			if err != nil && err.(syscall.Errno) != 0 {
				return nil
			}
			if status != hHIDP_STATUS_SUCCESS {
				return nil
			}

			rv.usagePage = caps.usagePage
			rv.usage = caps.usage
			rv.reportInputLength = caps.inputReportByteLength - 1
			rv.reportOutputLength = caps.outputReportByteLength - 1
			rv.reportFeatureLength = caps.featureReportByteLength - 1
			rv.reportWithId = true
			return rv
		}()

		if d != nil {
			rv = append(rv, d)
		}
	}

	return rv, nil
}

func (d *Device) open(lock bool) error {
	if d.extra.file != nil {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceIsOpen)
	}

	f, err := os.OpenFile(d.path, os.O_RDWR, 0755)
	if err != nil {
		return err
	}

	d.extra.file = f

	if lock {
		return d.lock()
	}
	return nil
}

func (d *Device) lock() error {
	if d.extra.file == nil {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceIsNotOpen)
	}

	hash := sha1.Sum([]byte(d.path))
	lockFile := path.Join(os.TempDir(), "usbhid-"+hex.EncodeToString(hash[:]))
	if maxPath := 260 - len(".lock") - 1; len(lockFile) > maxPath {
		lockFile = lockFile[:maxPath]
	}
	lockFile += ".lock"

	err := func() error {
		if err := os.WriteFile(lockFile, []byte{}, 0777); err != nil {
			return err
		}

		f, err := os.Open(lockFile)
		if err != nil {
			return err
		}

		ovl := &syscall.Overlapped{}
		_, _, err = lockFileEx.Call(f.Fd(), kLOCKFILE_EXCLUSIVE_LOCK|kLOCKFILE_FAIL_IMMEDIATELY, 0, 0xffffffff, 0xffffffff, uintptr(unsafe.Pointer(ovl)))
		if err != nil && err.(syscall.Errno) != 0 {
			f.Close()
			return err
		}
		d.extra.flock = f

		return nil
	}()

	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno == kERROR_LOCK_VIOLATION {
			return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceLocked)
		}
	}
	return err
}

func (d *Device) isOpen() bool {
	return d.extra.file != nil
}

func (d *Device) close() error {
	if d.extra.file == nil {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceIsNotOpen)
	}

	if err := d.extra.file.Close(); err != nil {
		return err
	}
	d.extra.file = nil

	if d.extra.flock != nil {
		fn := d.extra.flock.Name()
		if err := d.extra.flock.Close(); err != nil {
			return err
		}
		d.extra.flock = nil
		os.Remove(fn)
	}

	return nil
}

func (d *Device) getInputReport() (byte, []byte, error) {
	buf := make([]byte, d.reportInputLength+1)

	n, err := d.extra.file.Read(buf)
	if err != nil {
		return 0, nil, err
	}

	return buf[0], buf[1:n], nil
}

func (d *Device) setOutputReport(reportId byte, data []byte) error {
	buf := data
	if len(buf) >= int(d.reportOutputLength) {
		buf = buf[:d.reportOutputLength]
	} else {
		buf = append(buf, make([]byte, int(d.reportOutputLength)-len(buf))...)
	}
	buf = append([]byte{reportId}, buf...)
	_, err := d.extra.file.Write(buf)
	return err
}

func (d *Device) getFeatureReport(reportId byte) ([]byte, error) {
	buf := make([]byte, d.reportFeatureLength+1)
	buf[0] = reportId

	n, err := ioctl(d.extra.file.Fd(), kIOCTL_HID_GET_FEATURE, nil, buf)
	if err != nil && err.(syscall.Errno) != 0 {
		return nil, err
	}

	return buf[1:n], nil
}

func (d *Device) setFeatureReport(reportId byte, data []byte) error {
	buf := append([]byte{reportId}, data...)

	_, _, err := hidD_SetFeature.Call(d.extra.file.Fd(), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if err != nil && err.(syscall.Errno) != 0 {
		return err
	}

	return nil
}
