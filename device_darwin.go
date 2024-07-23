// Copyright 2022-2024 Rafael G. Martins. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package usbhid

import (
	"bytes"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

type deviceExtra struct {
	file    uintptr
	options uint32
	runloop uintptr

	mtx          sync.Mutex
	disconnect   bool
	disconnectCh chan bool
	inputBuffer  []byte
	inputCh      chan []byte
	inputClosed  bool
}

const (
	kCFAllocatorDefault uintptr = 0

	kCFNumberSInt16Type int64 = 2

	kCFStringEncodingUTF8 uint32 = 0x08000100

	kIOHIDOptionsTypeNone        uint32 = 0
	kIOHIDOptionsTypeSeizeDevice uint32 = 1

	kIOHIDReportTypeOutput  uint = 1
	kIOHIDReportTypeFeature uint = 2

	kIOReturnSuccess         int = 0
	kIOReturnExclusiveAccess int = 0xe00002c5
)

var (
	mgr uintptr

	_kCFRunLoopDefaultMode uintptr

	_CFNumberGetValue          func(number uintptr, theType int64, valuePtr unsafe.Pointer) bool
	_CFRelease                 func(cf uintptr)
	_CFRunLoopGetCurrent       func() uintptr
	_CFRunLoopRun              func()
	_CFRunLoopStop             func(runLoop uintptr)
	_CFSetGetCount             func(set uintptr) int
	_CFSetGetValues            func(set uintptr, value unsafe.Pointer) uintptr
	_CFStringCreateWithCString func(alloc uintptr, cstr []byte, encoding uint32) uintptr
	_CFStringGetCString        func(theString uintptr, buffer []byte, encoding uint32) bool

	_IOHIDDeviceClose                       func(device uintptr, options uint32) int
	_IOHIDDeviceCreate                      func(allocator uintptr, service uint32) uintptr
	_IOHIDDeviceGetProperty                 func(device uintptr, key uintptr) uintptr
	_IOHIDDeviceGetReport                   func(device uintptr, reportType uint, reportId int64, report []byte, pReportLength *int64) int
	_IOHIDDeviceGetService                  func(device uintptr) uint32
	_IOHIDDeviceOpen                        func(device uintptr, options uint32) int
	_IOHIDDeviceRegisterInputReportCallback func(device uintptr, report unsafe.Pointer, reportLength int64, callback uintptr, context unsafe.Pointer)
	_IOHIDDeviceRegisterRemovalCallback     func(device uintptr, callback uintptr, context unsafe.Pointer)
	_IOHIDDeviceScheduleWithRunLoop         func(device uintptr, runLoop uintptr, runLoopMode uintptr)
	_IOHIDDeviceSetReport                   func(device uintptr, reportType uint, reportID int64, report []byte, reportLength int64) int
	_IOHIDDeviceUnscheduleFromRunLoop       func(device uintptr, runLoop uintptr, runLoopMode uintptr)
	_IOHIDManagerClose                      func(manager uintptr, options uint32) int
	_IOHIDManagerCopyDevices                func(manager uintptr) uintptr
	_IOHIDManagerCreate                     func(allocator uintptr, options uint32) uintptr
	_IOHIDManagerOpen                       func(manager uintptr, options uint32) int
	_IOHIDManagerSetDeviceMatching          func(manager uintptr, matching uintptr)
	_IOObjectRelease                        func(object uint32) int
	_IORegistryEntryGetPath                 func(entry uint32, plane []byte, path []byte) int
	_IORegistryEntryGetRegistryEntryID      func(entry uint32, entryID *uint64) int
	_IORegistryEntryFromPath                func(mainPort uint32, path []byte) uint32
)

func init() {
	var err error

	cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		panic(err)
	}

	purego.RegisterLibFunc(&_CFNumberGetValue, cf, "CFNumberGetValue")
	purego.RegisterLibFunc(&_CFRelease, cf, "CFRelease")
	purego.RegisterLibFunc(&_CFRunLoopGetCurrent, cf, "CFRunLoopGetCurrent")
	purego.RegisterLibFunc(&_CFRunLoopRun, cf, "CFRunLoopRun")
	purego.RegisterLibFunc(&_CFRunLoopStop, cf, "CFRunLoopStop")
	purego.RegisterLibFunc(&_CFSetGetCount, cf, "CFSetGetCount")
	purego.RegisterLibFunc(&_CFSetGetValues, cf, "CFSetGetValues")
	purego.RegisterLibFunc(&_CFStringCreateWithCString, cf, "CFStringCreateWithCString")
	purego.RegisterLibFunc(&_CFStringGetCString, cf, "CFStringGetCString")

	_kCFRunLoopDefaultMode, err = purego.Dlsym(cf, "kCFRunLoopDefaultMode")
	if err != nil {
		panic(err)
	}

	iokit, err := purego.Dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		panic(err)
	}

	purego.RegisterLibFunc(&_IOHIDDeviceClose, iokit, "IOHIDDeviceClose")
	purego.RegisterLibFunc(&_IOHIDDeviceCreate, iokit, "IOHIDDeviceCreate")
	purego.RegisterLibFunc(&_IOHIDDeviceGetProperty, iokit, "IOHIDDeviceGetProperty")
	purego.RegisterLibFunc(&_IOHIDDeviceGetReport, iokit, "IOHIDDeviceGetReport")
	purego.RegisterLibFunc(&_IOHIDDeviceGetService, iokit, "IOHIDDeviceGetService")
	purego.RegisterLibFunc(&_IOHIDDeviceOpen, iokit, "IOHIDDeviceOpen")
	purego.RegisterLibFunc(&_IOHIDDeviceRegisterInputReportCallback, iokit, "IOHIDDeviceRegisterInputReportCallback")
	purego.RegisterLibFunc(&_IOHIDDeviceRegisterRemovalCallback, iokit, "IOHIDDeviceRegisterRemovalCallback")
	purego.RegisterLibFunc(&_IOHIDDeviceScheduleWithRunLoop, iokit, "IOHIDDeviceScheduleWithRunLoop")
	purego.RegisterLibFunc(&_IOHIDDeviceSetReport, iokit, "IOHIDDeviceSetReport")
	purego.RegisterLibFunc(&_IOHIDDeviceUnscheduleFromRunLoop, iokit, "IOHIDDeviceUnscheduleFromRunLoop")
	purego.RegisterLibFunc(&_IOHIDManagerClose, iokit, "IOHIDManagerClose")
	purego.RegisterLibFunc(&_IOHIDManagerCopyDevices, iokit, "IOHIDManagerCopyDevices")
	purego.RegisterLibFunc(&_IOHIDManagerCreate, iokit, "IOHIDManagerCreate")
	purego.RegisterLibFunc(&_IOHIDManagerOpen, iokit, "IOHIDManagerOpen")
	purego.RegisterLibFunc(&_IOHIDManagerSetDeviceMatching, iokit, "IOHIDManagerSetDeviceMatching")
	purego.RegisterLibFunc(&_IOObjectRelease, iokit, "IOObjectRelease")
	purego.RegisterLibFunc(&_IORegistryEntryGetPath, iokit, "IORegistryEntryGetPath")
	purego.RegisterLibFunc(&_IORegistryEntryGetRegistryEntryID, iokit, "IORegistryEntryGetRegistryEntryID")
	purego.RegisterLibFunc(&_IORegistryEntryFromPath, iokit, "IORegistryEntryFromPath")
}

func byteSliceToString(b []byte) string {
	if end := bytes.IndexByte(b, 0); end >= 0 {
		return string(b[:end])
	}
	return string(b)
}

func enumerate() ([]*Device, error) {
	if mgr == 0 {
		mgr = _IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone)
		if rv := _IOHIDManagerOpen(mgr, kIOHIDOptionsTypeNone); rv != kIOReturnSuccess {
			return nil, fmt.Errorf("usbhid: %w: 0x%08x", ErrHIDManagerOpen, rv)
		}
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
				options:      kIOHIDOptionsTypeNone,
				disconnectCh: make(chan bool),
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

func reportCallback(context unsafe.Pointer, result int, sender uintptr, reportType uintptr, reportId uint32, report uintptr, reportLength int64) {
	d := (*Device)(context)

	d.extra.mtx.Lock()
	defer d.extra.mtx.Unlock()

	if d.extra.inputBuffer != nil && !d.extra.inputClosed {
		select {
		case d.extra.inputCh <- append([]byte{}, d.extra.inputBuffer...):
		default:
		}
	}
}

func removalCallback(context unsafe.Pointer, result int, sender uintptr) {
	d := (*Device)(context)
	d.extra.disconnect = true
	d.extra.inputClosed = true
	close(d.extra.disconnectCh)
}

func (d *Device) open(lock bool) error {
	if d.extra.file != 0 {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceIsOpen)
	}

	d.extra.mtx.Lock()
	defer d.extra.mtx.Unlock()

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
	if rv := _IOHIDDeviceOpen(d.extra.file, d.extra.options); rv != kIOReturnSuccess {
		if rv == kIOReturnExclusiveAccess {
			return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceLocked)
		}
		return fmt.Errorf("usbhid: %s: %w: 0x%08x", d.path, ErrDeviceFailedToOpen, rv)
	}

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		d.extra.mtx.Lock()
		d.extra.runloop = _CFRunLoopGetCurrent()
		d.extra.inputBuffer = make([]byte, d.reportInputLength+1)
		d.extra.inputCh = make(chan []byte, 1024)

		_IOHIDDeviceScheduleWithRunLoop(d.extra.file, d.extra.runloop, **(**uintptr)(unsafe.Pointer(&_kCFRunLoopDefaultMode)))
		_IOHIDDeviceRegisterInputReportCallback(d.extra.file, unsafe.Pointer(&d.extra.inputBuffer[0]), int64(d.reportInputLength+1), purego.NewCallback(reportCallback), unsafe.Pointer(d))
		_IOHIDDeviceRegisterRemovalCallback(d.extra.file, purego.NewCallback(removalCallback), unsafe.Pointer(d))

		d.extra.mtx.Unlock()

		_CFRunLoopRun()

		d.extra.mtx.Lock()
		d.extra.inputClosed = true
		d.extra.mtx.Unlock()
	}()

	return nil
}

func (d *Device) isOpen() bool {
	return d.extra.file != 0
}

func (d *Device) close() error {
	if d.extra.file == 0 {
		if d.extra.disconnect {
			return nil
		}
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceIsNotOpen)
	}

	if !d.extra.disconnect {
		_IOHIDDeviceRegisterInputReportCallback(d.extra.file, unsafe.Pointer(&d.extra.inputBuffer[0]), int64(d.reportInputLength+1), 0, nil)
		_IOHIDDeviceRegisterRemovalCallback(d.extra.file, 0, nil)
		_IOHIDDeviceUnscheduleFromRunLoop(d.extra.file, d.extra.runloop, **(**uintptr)(unsafe.Pointer(&_kCFRunLoopDefaultMode)))
	}

	if d.extra.inputCh != nil && !d.extra.inputClosed {
		_CFRunLoopStop(d.extra.runloop)
	}

	if !d.extra.disconnect {
		if rv := _IOHIDDeviceClose(d.extra.file, d.extra.options); rv != kIOReturnSuccess {
			return fmt.Errorf("usbhid: %s: %w: 0x%08x", d.path, ErrDeviceFailedToClose, rv)
		}
	}

	_CFRelease(d.extra.file)
	d.extra.file = 0

	return nil
}

func (d *Device) getInputReport() (byte, []byte, error) {
	select {
	case rv := <-d.extra.inputCh:
		return rv[0], rv[1:], nil
	case <-d.extra.disconnectCh:
		if err := d.close(); err != nil {
			return 0, nil, err
		}
		return 0, nil, fmt.Errorf("usbhid: %s: %w: disconnected", d.path, ErrDeviceIsNotOpen)
	}
}

func (d *Device) setOutputReport(reportId byte, data []byte) error {
	d.extra.mtx.Lock()
	defer d.extra.mtx.Unlock()

	if d.extra.disconnect {
		if err := d.close(); err != nil {
			return err
		}
		return fmt.Errorf("usbhid: %s: %w: disconnected", d.path, ErrDeviceIsNotOpen)
	}

	buf := append([]byte{reportId}, data...)

	if rv := _IOHIDDeviceSetReport(d.extra.file, kIOHIDReportTypeOutput, int64(reportId), buf, int64(len(buf))); rv != kIOReturnSuccess {
		return fmt.Errorf("usbhid: %s: failed to set output report: 0x%08x", d.path, rv)
	}
	return nil
}

func (d *Device) getFeatureReport(reportId byte) ([]byte, error) {
	d.extra.mtx.Lock()
	defer d.extra.mtx.Unlock()

	if d.extra.disconnect {
		if err := d.close(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("usbhid: %s: %w: disconnected", d.path, ErrDeviceIsNotOpen)
	}

	buf := make([]byte, d.reportFeatureLength+1)
	l := int64(d.reportFeatureLength + 1)

	if rv := _IOHIDDeviceGetReport(d.extra.file, kIOHIDReportTypeFeature, int64(reportId), buf, &l); rv != kIOReturnSuccess {
		return nil, fmt.Errorf("usbhid: %s: failed to get feature report: 0x%08x", d.path, rv)
	}
	return buf[1:], nil
}

func (d *Device) setFeatureReport(reportId byte, data []byte) error {
	d.extra.mtx.Lock()
	defer d.extra.mtx.Unlock()

	if d.extra.disconnect {
		if err := d.close(); err != nil {
			return err
		}
		return fmt.Errorf("usbhid: %s: %w: disconnected", d.path, ErrDeviceIsNotOpen)
	}

	buf := append([]byte{reportId}, data...)

	if rv := _IOHIDDeviceSetReport(d.extra.file, kIOHIDReportTypeFeature, int64(reportId), buf, int64(len(buf))); rv != kIOReturnSuccess {
		return fmt.Errorf("usbhid: %s: failed to set feature report: 0x%08x", d.path, rv)
	}
	return nil
}
