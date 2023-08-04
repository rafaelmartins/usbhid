// Copyright 2022-2023 Rafael G.Martins. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package usbhid

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/ebitengine/purego"
)

type deviceExtra struct {
	file    uintptr
	options uint32
}

var (
	_CFSetGetCount             func(set uintptr) int
	_CFSetGetValues            func(set uintptr, value unsafe.Pointer) uintptr
	_CFStringCreateWithCString func(alloc uintptr, cstr []byte, encoding uint32) uintptr
	_CFNumberGetValue          func(number uintptr, theType uintptr, valuePtr unsafe.Pointer) bool
	_CFStringGetCString        func(theString uintptr, buffer []byte, encoding uint32) bool
	_CFRelease                 func(cf uintptr)

	_IOHIDManagerCreate                func(allocator uintptr, options uint32) uintptr
	_IOHIDManagerOpen                  func(manager uintptr, options uint32) int
	_IOHIDManagerCopyDevices           func(manager uintptr) uintptr
	_IOHIDManagerSetDeviceMatching     func(manager uintptr, matching uintptr)
	_IOHIDDeviceGetProperty            func(device uintptr, key uintptr) uintptr
	_IOHIDDeviceGetService             func(device uintptr) uintptr
	_IORegistryEntryGetRegistryEntryID func(entry uintptr, entryID *uint64) int
	_IORegistryEntryGetPath            func(entry uintptr, plane []byte, path []byte) int
	_IORegistryEntryFromPath           func(mainPort uintptr, path []byte) uintptr
	_IOHIDDeviceCreate                 func(allocator uintptr, service uintptr) uintptr
	_IOHIDDeviceOpen                   func(device uintptr, options uint32) int
	_IOHIDDeviceClose                  func(device uintptr, options uint32) int
	_IOObjectRelease                   func(object uintptr) int
)

const (
	kCFAllocatorDefault   uintptr = 0
	kCFNumberSInt16Type   uintptr = 2
	kCFNumberSInt32Type   uintptr = 3
	kCFNumberIntType      uintptr = 9
	kCFStringEncodingUTF8 uint32  = 0x08000100

	kIOHIDOptionsTypeNone        uint32 = 0
	kIOHIDOptionsTypeSeizeDevice uint32 = 1

	kIOReturnSuccess int = 0
)

func init() {
	var err error

	cf, err := purego.Dlopen("CoreFoundation.framework/CoreFoundation", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		panic(err)
	}

	purego.RegisterLibFunc(&_CFSetGetCount, cf, "CFSetGetCount")
	purego.RegisterLibFunc(&_CFSetGetValues, cf, "CFSetGetValues")
	purego.RegisterLibFunc(&_CFStringCreateWithCString, cf, "CFStringCreateWithCString")
	purego.RegisterLibFunc(&_CFNumberGetValue, cf, "CFNumberGetValue")
	purego.RegisterLibFunc(&_CFStringGetCString, cf, "CFStringGetCString")
	purego.RegisterLibFunc(&_CFRelease, cf, "CFRelease")

	iokit, err := purego.Dlopen("IOKit.framework/IOKit", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		panic(err)
	}

	purego.RegisterLibFunc(&_IOHIDManagerCreate, iokit, "IOHIDManagerCreate")
	purego.RegisterLibFunc(&_IOHIDManagerOpen, iokit, "IOHIDManagerOpen")
	purego.RegisterLibFunc(&_IOHIDManagerCopyDevices, iokit, "IOHIDManagerCopyDevices")
	purego.RegisterLibFunc(&_IOHIDManagerSetDeviceMatching, iokit, "IOHIDManagerSetDeviceMatching")
	purego.RegisterLibFunc(&_IOHIDDeviceGetProperty, iokit, "IOHIDDeviceGetProperty")
	purego.RegisterLibFunc(&_IOHIDDeviceGetService, iokit, "IOHIDDeviceGetService")
	purego.RegisterLibFunc(&_IORegistryEntryGetRegistryEntryID, iokit, "IORegistryEntryGetRegistryEntryID")
	purego.RegisterLibFunc(&_IORegistryEntryGetPath, iokit, "IORegistryEntryGetPath")
	purego.RegisterLibFunc(&_IORegistryEntryFromPath, iokit, "IORegistryEntryFromPath")
	purego.RegisterLibFunc(&_IOHIDDeviceCreate, iokit, "IOHIDDeviceCreate")
	purego.RegisterLibFunc(&_IOHIDDeviceOpen, iokit, "IOHIDDeviceOpen")
	purego.RegisterLibFunc(&_IOHIDDeviceClose, iokit, "IOHIDDeviceClose")
	purego.RegisterLibFunc(&_IOObjectRelease, iokit, "IOObjectRelease")
}

func byteSliceToString(b []byte) string {
	if end := bytes.IndexByte(b, 0); end >= 0 {
		return string(b[:end])
	}
	return string(b)
}

func enumerate() ([]*Device, error) {
	mgr := _IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone)
	if _IOHIDManagerOpen(mgr, kIOHIDOptionsTypeNone) != kIOReturnSuccess {
		return nil, fmt.Errorf("usbhid: %w", ErrHIDManagerOpen)
	}
	_IOHIDManagerSetDeviceMatching(mgr, 0)

	device_set := _IOHIDManagerCopyDevices(mgr)
	defer _CFRelease(device_set)

	devices := make([]uintptr, _CFSetGetCount(device_set))
	_CFSetGetValues(device_set, unsafe.Pointer(&devices[0]))

	buf := make([]byte, 2048)

	rv := []*Device{}
	for _, device := range devices {
		var path string
		if svc := _IOHIDDeviceGetService(device); svc != 0 {
			plane := make([]byte, 128)
			copy(plane[:], "IOService")

			pathB := make([]byte, 512)
			if r := _IORegistryEntryGetPath(svc, plane, pathB); r == 0 {
				path = byteSliceToString(pathB)
			}
		}
		if path == "" {
			continue
		}

		if prop := _IOHIDDeviceGetProperty(device, _CFStringCreateWithCString(kCFAllocatorDefault, []byte("Transport"), kCFStringEncodingUTF8)); prop != 0 {
			_CFStringGetCString(prop, buf[:], kCFStringEncodingUTF8)
			if transport := byteSliceToString(buf[:]); transport != "USB" {
				continue
			}
		} else {
			continue
		}

		dev := &Device{
			path: path,
			extra: deviceExtra{
				options: kIOHIDOptionsTypeNone,
			},
		}

		if prop := _IOHIDDeviceGetProperty(device, _CFStringCreateWithCString(kCFAllocatorDefault, []byte("VendorID"), kCFStringEncodingUTF8)); prop != 0 {
			_CFNumberGetValue(prop, kCFNumberSInt16Type, unsafe.Pointer(&dev.vendorId))
		}

		if prop := _IOHIDDeviceGetProperty(device, _CFStringCreateWithCString(kCFAllocatorDefault, []byte("ProductID"), kCFStringEncodingUTF8)); prop != 0 {
			_CFNumberGetValue(prop, kCFNumberSInt16Type, unsafe.Pointer(&dev.productId))
		}

		if prop := _IOHIDDeviceGetProperty(device, _CFStringCreateWithCString(kCFAllocatorDefault, []byte("VersionNumber"), kCFStringEncodingUTF8)); prop != 0 {
			_CFNumberGetValue(prop, kCFNumberSInt16Type, unsafe.Pointer(&dev.version))
		}

		if prop := _IOHIDDeviceGetProperty(device, _CFStringCreateWithCString(kCFAllocatorDefault, []byte("PrimaryUsagePage"), kCFStringEncodingUTF8)); prop != 0 {
			_CFNumberGetValue(prop, kCFNumberSInt16Type, unsafe.Pointer(&dev.usagePage))
		}

		if prop := _IOHIDDeviceGetProperty(device, _CFStringCreateWithCString(kCFAllocatorDefault, []byte("PrimaryUsage"), kCFStringEncodingUTF8)); prop != 0 {
			_CFNumberGetValue(prop, kCFNumberSInt16Type, unsafe.Pointer(&dev.usage))
		}

		if prop := _IOHIDDeviceGetProperty(device, _CFStringCreateWithCString(kCFAllocatorDefault, []byte("MaxInputReportSize"), kCFStringEncodingUTF8)); prop != 0 {
			_CFNumberGetValue(prop, kCFNumberSInt16Type, unsafe.Pointer(&dev.reportInputLength))
			dev.reportInputLength--
		}

		if prop := _IOHIDDeviceGetProperty(device, _CFStringCreateWithCString(kCFAllocatorDefault, []byte("MaxOutputReportSize"), kCFStringEncodingUTF8)); prop != 0 {
			_CFNumberGetValue(prop, kCFNumberSInt16Type, unsafe.Pointer(&dev.reportOutputLength))
			dev.reportOutputLength--
		}

		if prop := _IOHIDDeviceGetProperty(device, _CFStringCreateWithCString(kCFAllocatorDefault, []byte("MaxFeatureReportSize"), kCFStringEncodingUTF8)); prop != 0 {
			_CFNumberGetValue(prop, kCFNumberSInt16Type, unsafe.Pointer(&dev.reportFeatureLength))
			dev.reportFeatureLength--
		}

		if prop := _IOHIDDeviceGetProperty(device, _CFStringCreateWithCString(kCFAllocatorDefault, []byte("Manufacturer"), kCFStringEncodingUTF8)); prop != 0 {
			_CFStringGetCString(prop, buf[:], kCFStringEncodingUTF8)
			dev.manufacturer = byteSliceToString(buf[:])
		}

		if prop := _IOHIDDeviceGetProperty(device, _CFStringCreateWithCString(kCFAllocatorDefault, []byte("Product"), kCFStringEncodingUTF8)); prop != 0 {
			_CFStringGetCString(prop, buf[:], kCFStringEncodingUTF8)
			dev.product = byteSliceToString(buf[:])
		}

		if prop := _IOHIDDeviceGetProperty(device, _CFStringCreateWithCString(kCFAllocatorDefault, []byte("SerialNumber"), kCFStringEncodingUTF8)); prop != 0 {
			_CFStringGetCString(prop, buf[:], kCFStringEncodingUTF8)
			dev.serialNumber = byteSliceToString(buf[:])
		}

		dev.reportWithId = true

		rv = append(rv, dev)
	}

	return rv, nil
}

func (d *Device) open(lock bool) error {
	if d.extra.file != 0 {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceIsOpen)
	}

	pathB := make([]byte, 512)
	copy(pathB[:], d.path)
	entry := _IORegistryEntryFromPath(0, pathB)
	if entry == 0 {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceFailedToOpen)
	}
	defer _IOObjectRelease(entry)

	d.extra.file = _IOHIDDeviceCreate(kCFAllocatorDefault, entry)
	if d.extra.file == 0 {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceFailedToOpen)
	}

	if lock {
		d.extra.options = kIOHIDOptionsTypeSeizeDevice
	}
	if _IOHIDDeviceOpen(d.extra.file, d.extra.options) != kIOReturnSuccess {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceFailedToOpen)
	}

	return nil
}

func (d *Device) isOpen() bool {
	return d.extra.file != 0
}

func (d *Device) close() error {
	if d.extra.file == 0 {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceIsNotOpen)
	}

	if _IOHIDDeviceClose(d.extra.file, d.extra.options) != kIOReturnSuccess {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceFailedToClose)
	}
	_CFRelease(d.extra.file)

	return nil
}

func (d *Device) getInputReport() (byte, []byte, error) {
	return 0, nil, nil
}

func (d *Device) setOutputReport(reportId byte, data []byte) error {
	return nil
}

func (d *Device) getFeatureReport(reportId byte) ([]byte, error) {
	return nil, nil
}

func (d *Device) setFeatureReport(reportId byte, data []byte) error {
	return nil
}
