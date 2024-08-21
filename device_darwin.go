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
	inputCh      chan inputCtx
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

type _CFRange struct {
	location int64
	length   int64
}

var (
	mgr uintptr

	_kCFRunLoopDefaultMode uintptr

	_CFDataGetBytes            func(data uintptr, rang _CFRange, buffer []byte)
	_CFDataGetLength           func(data uintptr) int64
	_CFNumberGetValue          func(number uintptr, theType int64, valuePtr unsafe.Pointer) bool
	_CFRelease                 func(cf uintptr)
	_CFRunLoopGetCurrent       func() uintptr
	_CFRunLoopRun              func()
	_CFRunLoopStop             func(runLoop uintptr)
	_CFSetGetCount             func(set uintptr) int
	_CFSetGetValues            func(set uintptr, value unsafe.Pointer) uintptr
	_CFStringCreateWithCString func(alloc uintptr, cstr []byte, encoding uint32) uintptr
	_CFStringGetCString        func(theString uintptr, buffer []byte, encoding uint32) bool
	_CFStringGetLength         func(theString uintptr) int64

	_IOHIDDeviceClose                       func(device uintptr, options uint32) int
	_IOHIDDeviceCreate                      func(allocator uintptr, service uint32) uintptr
	_IOHIDDeviceGetProperty                 func(device uintptr, key uintptr) uintptr
	_IOHIDDeviceGetReportWithCallback       func(device uintptr, reportType uint, reportId int64, report []byte, pReportLength *int64, timeout float64, callback uintptr, context unsafe.Pointer) int
	_IOHIDDeviceGetService                  func(device uintptr) uint32
	_IOHIDDeviceOpen                        func(device uintptr, options uint32) int
	_IOHIDDeviceRegisterInputReportCallback func(device uintptr, report unsafe.Pointer, reportLength int64, callback uintptr, context unsafe.Pointer)
	_IOHIDDeviceRegisterRemovalCallback     func(device uintptr, callback uintptr, context unsafe.Pointer)
	_IOHIDDeviceScheduleWithRunLoop         func(device uintptr, runLoop uintptr, runLoopMode uintptr)
	_IOHIDDeviceSetReportWithCallback       func(device uintptr, reportType uint, reportID int64, report []byte, reportLength int64, timeout float64, callback uintptr, context unsafe.Pointer)
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

	purego.RegisterLibFunc(&_CFDataGetBytes, cf, "CFDataGetBytes")
	purego.RegisterLibFunc(&_CFDataGetLength, cf, "CFDataGetLength")
	purego.RegisterLibFunc(&_CFNumberGetValue, cf, "CFNumberGetValue")
	purego.RegisterLibFunc(&_CFRelease, cf, "CFRelease")
	purego.RegisterLibFunc(&_CFRunLoopGetCurrent, cf, "CFRunLoopGetCurrent")
	purego.RegisterLibFunc(&_CFRunLoopRun, cf, "CFRunLoopRun")
	purego.RegisterLibFunc(&_CFRunLoopStop, cf, "CFRunLoopStop")
	purego.RegisterLibFunc(&_CFSetGetCount, cf, "CFSetGetCount")
	purego.RegisterLibFunc(&_CFSetGetValues, cf, "CFSetGetValues")
	purego.RegisterLibFunc(&_CFStringCreateWithCString, cf, "CFStringCreateWithCString")
	purego.RegisterLibFunc(&_CFStringGetCString, cf, "CFStringGetCString")
	purego.RegisterLibFunc(&_CFStringGetLength, cf, "CFStringGetLength")

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
	purego.RegisterLibFunc(&_IOHIDDeviceGetReportWithCallback, iokit, "IOHIDDeviceGetReportWithCallback")
	purego.RegisterLibFunc(&_IOHIDDeviceGetService, iokit, "IOHIDDeviceGetService")
	purego.RegisterLibFunc(&_IOHIDDeviceOpen, iokit, "IOHIDDeviceOpen")
	purego.RegisterLibFunc(&_IOHIDDeviceRegisterInputReportCallback, iokit, "IOHIDDeviceRegisterInputReportCallback")
	purego.RegisterLibFunc(&_IOHIDDeviceRegisterRemovalCallback, iokit, "IOHIDDeviceRegisterRemovalCallback")
	purego.RegisterLibFunc(&_IOHIDDeviceScheduleWithRunLoop, iokit, "IOHIDDeviceScheduleWithRunLoop")
	purego.RegisterLibFunc(&_IOHIDDeviceSetReportWithCallback, iokit, "IOHIDDeviceSetReportWithCallback")
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

func cfstringToString(str uintptr) string {
	buf := make([]byte, _CFStringGetLength(str)+1)
	if _CFStringGetCString(str, buf[:], kCFStringEncodingUTF8) {
		return byteSliceToString(buf[:])
	}
	return ""
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

	sManufacturer := _CFStringCreateWithCString(kCFAllocatorDefault, []byte("Manufacturer"), kCFStringEncodingUTF8)
	sProduct := _CFStringCreateWithCString(kCFAllocatorDefault, []byte("Product"), kCFStringEncodingUTF8)
	sProductID := _CFStringCreateWithCString(kCFAllocatorDefault, []byte("ProductID"), kCFStringEncodingUTF8)
	sReportDescriptor := _CFStringCreateWithCString(kCFAllocatorDefault, []byte("ReportDescriptor"), kCFStringEncodingUTF8)
	sSerialNumber := _CFStringCreateWithCString(kCFAllocatorDefault, []byte("SerialNumber"), kCFStringEncodingUTF8)
	sTransport := _CFStringCreateWithCString(kCFAllocatorDefault, []byte("Transport"), kCFStringEncodingUTF8)
	sVendorID := _CFStringCreateWithCString(kCFAllocatorDefault, []byte("VendorID"), kCFStringEncodingUTF8)
	sVersionNumber := _CFStringCreateWithCString(kCFAllocatorDefault, []byte("VersionNumber"), kCFStringEncodingUTF8)
	if sManufacturer == 0 || sProduct == 0 || sProductID == 0 || sReportDescriptor == 0 || sSerialNumber == 0 || sTransport == 0 || sVendorID == 0 || sVersionNumber == 0 {
		panic("failed to allocate memory for property key strings")
	}
	defer func() {
		_CFRelease(sManufacturer)
		_CFRelease(sProduct)
		_CFRelease(sProductID)
		_CFRelease(sReportDescriptor)
		_CFRelease(sSerialNumber)
		_CFRelease(sTransport)
		_CFRelease(sVendorID)
		_CFRelease(sVersionNumber)
	}()

	bIOService := make([]byte, 128)
	copy(bIOService[:], "IOService")

	rv := []*Device{}
	for _, device := range devices {
		path := ""
		if svc := _IOHIDDeviceGetService(device); svc != 0 {
			pathB := make([]byte, 512)
			if _IORegistryEntryGetPath(svc, bIOService, pathB) == 0 {
				path = byteSliceToString(pathB)
			}
		}
		if path == "" {
			continue
		}

		if prop := _IOHIDDeviceGetProperty(device, sTransport); prop != 0 {
			if transport := cfstringToString(prop); transport != "USB" {
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

		if prop := _IOHIDDeviceGetProperty(device, sVendorID); prop != 0 {
			_CFNumberGetValue(prop, kCFNumberSInt16Type, unsafe.Pointer(&dev.vendorId))
		}

		if prop := _IOHIDDeviceGetProperty(device, sProductID); prop != 0 {
			_CFNumberGetValue(prop, kCFNumberSInt16Type, unsafe.Pointer(&dev.productId))
		}

		if prop := _IOHIDDeviceGetProperty(device, sVersionNumber); prop != 0 {
			_CFNumberGetValue(prop, kCFNumberSInt16Type, unsafe.Pointer(&dev.version))
		}

		if prop := _IOHIDDeviceGetProperty(device, sManufacturer); prop != 0 {
			dev.manufacturer = cfstringToString(prop)
		}

		if prop := _IOHIDDeviceGetProperty(device, sProduct); prop != 0 {
			dev.product = cfstringToString(prop)
		}

		if prop := _IOHIDDeviceGetProperty(device, sSerialNumber); prop != 0 {
			dev.serialNumber = cfstringToString(prop)
		}

		descriptor := []byte{}
		if prop := _IOHIDDeviceGetProperty(device, sReportDescriptor); prop != 0 {
			l := _CFDataGetLength(prop)
			buf := make([]byte, l)
			_CFDataGetBytes(prop, _CFRange{0, l}, buf[:])
			descriptor = append(descriptor, buf[:]...)
		}

		dev.usagePage, dev.usage, dev.reportInputLength, dev.reportOutputLength, dev.reportFeatureLength, dev.reportWithId = hidParseReportDescriptor(descriptor)

		rv = append(rv, dev)
	}

	return rv, nil
}

type inputCtx struct {
	buf []byte
	err error
}

func inputCallback(context unsafe.Pointer, result int, sender uintptr, reportType uintptr, reportId uint32, report uintptr, reportLength int64) {
	d := (*Device)(context)

	d.extra.mtx.Lock()
	defer d.extra.mtx.Unlock()

	if d.extra.inputClosed {
		return
	}

	ctx := inputCtx{}
	if result != kIOReturnSuccess {
		ctx.err = fmt.Errorf("usbhid: %s: failed to get input report: 0x%08x", d.path, result)
	} else if d.extra.inputBuffer == nil {
		ctx.err = fmt.Errorf("usbhid: %s: failed to get input report: buffer is nil", d.path)
	} else {
		ctx.buf = append([]byte{}, d.extra.inputBuffer[:reportLength]...)
	}

	select {
	case d.extra.inputCh <- ctx:
	default:
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

	wait := make(chan struct{})

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		d.extra.runloop = _CFRunLoopGetCurrent()
		d.extra.inputBuffer = make([]byte, d.reportInputLength+1)
		d.extra.inputCh = make(chan inputCtx)

		_IOHIDDeviceScheduleWithRunLoop(d.extra.file, d.extra.runloop, **(**uintptr)(unsafe.Pointer(&_kCFRunLoopDefaultMode)))
		_IOHIDDeviceRegisterInputReportCallback(d.extra.file, unsafe.Pointer(&d.extra.inputBuffer[0]), int64(d.reportInputLength+1), purego.NewCallback(inputCallback), unsafe.Pointer(d))
		_IOHIDDeviceRegisterRemovalCallback(d.extra.file, purego.NewCallback(removalCallback), unsafe.Pointer(d))

		wait <- struct{}{}

		_CFRunLoopRun()

		d.extra.mtx.Lock()
		defer d.extra.mtx.Unlock()

		d.extra.inputClosed = true
	}()

	<-wait

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
	case result := <-d.extra.inputCh:
		if result.err != nil {
			return 0, nil, result.err
		}

		if d.reportWithId {
			return result.buf[0], result.buf[1:], nil
		}
		return 0, result.buf[:], nil

	case <-d.extra.disconnectCh:
		if err := d.close(); err != nil {
			return 0, nil, err
		}
		return 0, nil, fmt.Errorf("usbhid: %s: %w: disconnected", d.path, ErrDeviceIsNotOpen)
	}
}

type resultCtx struct {
	device *Device
	op     string
	len    int64
	err    chan error
}

func resultCallback(context unsafe.Pointer, result int, sender uintptr, reportType uint, reportId uint32, report uintptr, reportLength int64) {
	ctx := (*resultCtx)(context)

	var err error
	if result != kIOReturnSuccess {
		typ := "report"
		switch reportType {
		case kIOHIDReportTypeOutput:
			typ = "output report"
		case kIOHIDReportTypeFeature:
			typ = "feature report"
		}
		err = fmt.Errorf("usbhid: %s: failed to %s %s: 0x%08x", ctx.device.path, ctx.op, typ, result)
	}

	ctx.len = reportLength
	ctx.err <- err
}

func (d *Device) setReport(typ uint, reportId byte, data []byte) error {
	if d.extra.disconnect {
		if err := d.close(); err != nil {
			return err
		}
		return fmt.Errorf("usbhid: %s: %w: disconnected", d.path, ErrDeviceIsNotOpen)
	}

	ctx := &resultCtx{
		device: d,
		op:     "set",
		err:    make(chan error),
	}
	buf := append([]byte{}, data...)
	if d.reportWithId {
		buf = append([]byte{reportId}, buf...)
	}
	_IOHIDDeviceSetReportWithCallback(d.extra.file, typ, int64(reportId), buf, int64(len(buf)), 0, purego.NewCallback(resultCallback), unsafe.Pointer(ctx))

	return <-ctx.err
}

func (d *Device) setOutputReport(reportId byte, data []byte) error {
	return d.setReport(kIOHIDReportTypeOutput, reportId, data)
}

func (d *Device) setFeatureReport(reportId byte, data []byte) error {
	return d.setReport(kIOHIDReportTypeFeature, reportId, data)
}

func (d *Device) getFeatureReport(reportId byte) ([]byte, error) {
	if d.extra.disconnect {
		if err := d.close(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("usbhid: %s: %w: disconnected", d.path, ErrDeviceIsNotOpen)
	}

	ctx := &resultCtx{
		device: d,
		op:     "get",
		err:    make(chan error),
	}
	buf := make([]byte, d.reportFeatureLength+1)
	l := int64(d.reportFeatureLength + 1)
	if rv := _IOHIDDeviceGetReportWithCallback(d.extra.file, kIOHIDReportTypeFeature, int64(reportId), buf, &l, 0, purego.NewCallback(resultCallback), unsafe.Pointer(ctx)); rv != kIOReturnSuccess {
		return nil, fmt.Errorf("usbhid: %s: failed to register callback to get feature report: 0x%08x", d.path, rv)
	}

	if err := <-ctx.err; err != nil {
		return nil, err
	}

	if d.reportWithId {
		return buf[1:ctx.len], nil
	}
	return buf[:ctx.len], nil
}
