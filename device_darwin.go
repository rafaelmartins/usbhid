// Copyright 2022-2024 Rafael G. Martins. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package usbhid

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

type (
	_io_name_t           []byte
	_io_object_t         = _mach_port_t
	_io_registry_entry_t = _io_object_t
	_io_service_t        = _io_object_t
	_io_string_t         []byte
	_kern_return_t       int32
	_mach_port_t         uint32
)

type (
	_CFAllocatorRef  uintptr
	_CFDataRef       uintptr
	_CFDictionaryRef uintptr
	_CFIndex         int64
	_CFNumberRef     uintptr
	_CFNumberType    = _CFIndex
	_CFRange         struct {
		location _CFIndex
		length   _CFIndex
	}
	_CFRunLoopRef     uintptr
	_CFSetRef         uintptr
	_CFStringEncoding uint32
	_CFStringRef      uintptr
	_CFTimeInterval   float64
	_CFTypeRef        uintptr
)

type (
	_IOHIDDeviceRef  uintptr
	_IOHIDManagerRef uintptr
	_IOHIDReportType uint32
	_IOOptionBits    uint32
	_IOReturn        = _kern_return_t
)

type deviceExtra struct {
	file    _IOHIDDeviceRef
	options _IOOptionBits
	runloop _CFRunLoopRef

	mtx          sync.Mutex
	disconnect   bool
	disconnectCh chan bool
	inputBuffer  []byte
	inputCh      chan inputCtx
	inputClosed  bool
}

const (
	kCFAllocatorDefault _CFAllocatorRef = 0

	kCFNumberSInt16Type _CFIndex = 2

	kCFStringEncodingUTF8 _CFStringEncoding = 0x08000100
)

var (
	_CFDataGetBytes          func(data _CFDataRef, rang _CFRange, buffer []byte)
	_CFDataGetLength         func(data _CFDataRef) _CFIndex
	_CFNumberGetValue        func(number _CFNumberRef, theType _CFNumberType, valuePtr unsafe.Pointer) bool
	_CFRelease               func(cf _CFTypeRef)
	_CFRunLoopGetCurrent     func() _CFRunLoopRef
	_CFRunLoopRun            func()
	_CFRunLoopStop           func(runLoop _CFRunLoopRef)
	_CFSetGetCount           func(theSet _CFSetRef) _CFIndex
	_CFSetGetValues          func(theSet _CFSetRef, value unsafe.Pointer)
	_CFStringCreateWithBytes func(alloc _CFAllocatorRef, bytes []byte, numBytes _CFIndex, encoding _CFStringEncoding, isExternalRepresentation bool) _CFStringRef
	_CFStringGetCString      func(theString _CFStringRef, buffer []byte, encoding _CFStringEncoding) bool
	_CFStringGetLength       func(theString _CFStringRef) _CFIndex
)

var _kCFRunLoopDefaultMode uintptr

const (
	kIOHIDOptionsTypeNone        _IOOptionBits = 0
	kIOHIDOptionsTypeSeizeDevice _IOOptionBits = 1

	kIOHIDReportTypeOutput  _IOHIDReportType = 1
	kIOHIDReportTypeFeature _IOHIDReportType = 2

	kIOReturnSuccess         _IOReturn = 0
	kIOReturnExclusiveAccess _IOReturn = -0x1ffffd3b
)

var (
	_IOHIDDeviceClose                       func(device _IOHIDDeviceRef, options _IOOptionBits) _IOReturn
	_IOHIDDeviceCreate                      func(allocator _CFAllocatorRef, service _io_service_t) _IOHIDDeviceRef
	_IOHIDDeviceGetProperty                 func(device _IOHIDDeviceRef, key _CFStringRef) _CFTypeRef
	_IOHIDDeviceGetReportWithCallback       func(device _IOHIDDeviceRef, reportType _IOHIDReportType, reportId _CFIndex, report []byte, pReportLength *_CFIndex, timeout _CFTimeInterval, callback uintptr, context unsafe.Pointer) _IOReturn
	_IOHIDDeviceGetService                  func(device _IOHIDDeviceRef) _io_service_t
	_IOHIDDeviceOpen                        func(device _IOHIDDeviceRef, options _IOOptionBits) _IOReturn
	_IOHIDDeviceRegisterInputReportCallback func(device _IOHIDDeviceRef, report unsafe.Pointer, reportLength _CFIndex, callback uintptr, context unsafe.Pointer)
	_IOHIDDeviceRegisterRemovalCallback     func(device _IOHIDDeviceRef, callback uintptr, context unsafe.Pointer)
	_IOHIDDeviceScheduleWithRunLoop         func(device _IOHIDDeviceRef, runLoop _CFRunLoopRef, runLoopMode _CFStringRef)
	_IOHIDDeviceSetReportWithCallback       func(device _IOHIDDeviceRef, reportType _IOHIDReportType, reportID _CFIndex, report []byte, reportLength _CFIndex, timeout _CFTimeInterval, callback uintptr, context unsafe.Pointer)
	_IOHIDDeviceUnscheduleFromRunLoop       func(device _IOHIDDeviceRef, runLoop _CFRunLoopRef, runLoopMode _CFStringRef)
	_IOHIDManagerClose                      func(manager _IOHIDManagerRef, options _IOOptionBits) _IOReturn
	_IOHIDManagerCopyDevices                func(manager _IOHIDManagerRef) _CFSetRef
	_IOHIDManagerCreate                     func(allocator _CFAllocatorRef, options _IOOptionBits) _IOHIDManagerRef
	_IOHIDManagerOpen                       func(manager _IOHIDManagerRef, options _IOOptionBits) _IOReturn
	_IOHIDManagerSetDeviceMatching          func(manager _IOHIDManagerRef, matching _CFDictionaryRef)
	_IOObjectRelease                        func(object _io_object_t) _kern_return_t
	_IORegistryEntryGetPath                 func(entry _io_registry_entry_t, plane _io_name_t, path _io_string_t) _kern_return_t
	_IORegistryEntryGetRegistryEntryID      func(entry _io_registry_entry_t, entryID *uint64) _kern_return_t
	_IORegistryEntryFromPath                func(mainPort _mach_port_t, path _io_string_t) _io_registry_entry_t
)

var (
	mgr _IOHIDManagerRef

	inputCallbackPtr   = purego.NewCallback(inputCallback)
	removalCallbackPtr = purego.NewCallback(removalCallback)
	resultCallbackPtr  = purego.NewCallback(resultCallback)
)

func init() {
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
	purego.RegisterLibFunc(&_CFStringCreateWithBytes, cf, "CFStringCreateWithBytes")
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

	mgr = _IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone)
	if rv := _IOHIDManagerOpen(mgr, kIOHIDOptionsTypeNone); rv != kIOReturnSuccess {
		panic("failed to create iohid manager")
	}
}

func byteSliceToString(b []byte) string {
	if end := bytes.IndexByte(b, 0); end >= 0 {
		return string(b[:end])
	}
	return string(b)
}

func cfstringToString(str _CFStringRef) (string, error) {
	buf := make([]byte, _CFStringGetLength(str)+1)
	if !_CFStringGetCString(str, buf[:], kCFStringEncodingUTF8) {
		return "", errors.New("failed to convert string")
	}
	return byteSliceToString(buf[:]), nil
}

func getProperty(device _IOHIDDeviceRef, key string) (_CFTypeRef, error) {
	bkey := []byte(key)
	skey := _CFStringCreateWithBytes(kCFAllocatorDefault, bkey, _CFIndex(len(bkey)), kCFStringEncodingUTF8, false)
	if skey == 0 {
		return 0, fmt.Errorf("failed to allocate memory for device property lookup key: %s", key)
	}
	defer _CFRelease(_CFTypeRef(skey))

	prop := _IOHIDDeviceGetProperty(device, skey)
	if prop == 0 {
		return 0, fmt.Errorf("failed to retrieve device property: %s", key)
	}
	return prop, nil
}

func getPropertyUint16(device _IOHIDDeviceRef, key string) (uint16, error) {
	prop, err := getProperty(device, key)
	if err != nil {
		return 0, err
	}

	rv := uint16(0)
	if !_CFNumberGetValue(_CFNumberRef(prop), kCFNumberSInt16Type, unsafe.Pointer(&rv)) {
		return 0, fmt.Errorf("failed to convert property to uint16: %s", key)
	}
	return rv, nil
}

func getPropertyString(device _IOHIDDeviceRef, key string) (string, error) {
	prop, err := getProperty(device, key)
	if err != nil {
		return "", err
	}
	return cfstringToString(_CFStringRef(prop))
}

func enumerate() ([]*Device, error) {
	_IOHIDManagerSetDeviceMatching(mgr, 0)

	device_set := _IOHIDManagerCopyDevices(mgr)
	defer _CFRelease(_CFTypeRef(device_set))

	devices := make([]_IOHIDDeviceRef, _CFSetGetCount(device_set))
	_CFSetGetValues(device_set, unsafe.Pointer(&devices[0]))

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

		if transport, err := getPropertyString(device, "Transport"); err != nil || transport != "USB" {
			continue
		}

		dev := &Device{
			path: path,
			extra: deviceExtra{
				options:      kIOHIDOptionsTypeNone,
				disconnectCh: make(chan bool),
			},
		}

		// FIXME: not all errors should be ignored
		if prop, err := getPropertyUint16(device, "VendorID"); err == nil {
			dev.vendorId = prop
		}
		if prop, err := getPropertyUint16(device, "ProductID"); err == nil {
			dev.productId = prop
		}
		if prop, err := getPropertyUint16(device, "VersionNumber"); err == nil {
			dev.version = prop
		}
		if prop, err := getPropertyString(device, "Manufacturer"); err == nil {
			dev.manufacturer = prop
		}
		if prop, err := getPropertyString(device, "Product"); err == nil {
			dev.product = prop
		}
		if prop, err := getPropertyString(device, "SerialNumber"); err == nil {
			dev.serialNumber = prop
		}

		descriptor := []byte{}
		if prop, err := getProperty(device, "ReportDescriptor"); err == nil {
			l := _CFDataGetLength(_CFDataRef(prop))
			buf := make([]byte, l)
			_CFDataGetBytes(_CFDataRef(prop), _CFRange{0, l}, buf[:])
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

func inputCallback(context unsafe.Pointer, result _IOReturn, sender uintptr, reportType _IOHIDReportType, reportId uint32, report uintptr, reportLength _CFIndex) {
	d := (*Device)(context)

	d.extra.mtx.Lock()
	defer d.extra.mtx.Unlock()

	if d.extra.inputClosed {
		return
	}

	ctx := inputCtx{}
	if result != kIOReturnSuccess {
		ctx.err = fmt.Errorf("0x%08x", result)
	} else if d.extra.inputBuffer == nil {
		ctx.err = errors.New("buffer is nil")
	} else {
		ctx.buf = append([]byte{}, d.extra.inputBuffer[:reportLength]...)
	}

	select {
	case d.extra.inputCh <- ctx:
	default:
	}
}

func removalCallback(context unsafe.Pointer, result _IOReturn, sender uintptr) {
	d := (*Device)(context)

	d.extra.disconnect = true
	d.extra.inputClosed = true
	close(d.extra.disconnectCh)
}

func (d *Device) open(lock bool) error {
	d.extra.mtx.Lock()
	defer d.extra.mtx.Unlock()

	pathB := make([]byte, 512)
	copy(pathB[:], d.path)
	entry := _IORegistryEntryFromPath(0, pathB)
	if entry == 0 {
		return errors.New("failed to lookup io registry entry from path")
	}
	defer _IOObjectRelease(entry)

	d.extra.file = _IOHIDDeviceCreate(kCFAllocatorDefault, entry)
	if d.extra.file == 0 {
		return errors.New("failed to create iohid device")
	}

	if lock {
		d.extra.options = kIOHIDOptionsTypeSeizeDevice
	}
	if rv := _IOHIDDeviceOpen(d.extra.file, d.extra.options); rv != kIOReturnSuccess {
		if rv == kIOReturnExclusiveAccess {
			return ErrDeviceLocked
		}
		return fmt.Errorf("0x%08x", rv)
	}

	wait := make(chan struct{})

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		d.extra.runloop = _CFRunLoopGetCurrent()
		d.extra.inputBuffer = make([]byte, d.reportInputLength+1)
		d.extra.inputCh = make(chan inputCtx)

		_IOHIDDeviceScheduleWithRunLoop(d.extra.file, d.extra.runloop, **(**_CFStringRef)(unsafe.Pointer(&_kCFRunLoopDefaultMode)))
		_IOHIDDeviceRegisterInputReportCallback(d.extra.file, unsafe.Pointer(&d.extra.inputBuffer[0]), _CFIndex(d.reportInputLength+1), inputCallbackPtr, unsafe.Pointer(d))
		_IOHIDDeviceRegisterRemovalCallback(d.extra.file, removalCallbackPtr, unsafe.Pointer(d))

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
	if !d.extra.disconnect {
		_IOHIDDeviceRegisterInputReportCallback(d.extra.file, unsafe.Pointer(&d.extra.inputBuffer[0]), _CFIndex(d.reportInputLength+1), 0, nil)
		_IOHIDDeviceRegisterRemovalCallback(d.extra.file, 0, nil)
		_IOHIDDeviceUnscheduleFromRunLoop(d.extra.file, d.extra.runloop, **(**_CFStringRef)(unsafe.Pointer(&_kCFRunLoopDefaultMode)))
	}

	if d.extra.inputCh != nil && !d.extra.inputClosed {
		_CFRunLoopStop(d.extra.runloop)
	}

	if !d.extra.disconnect {
		if rv := _IOHIDDeviceClose(d.extra.file, d.extra.options); rv != kIOReturnSuccess {
			return fmt.Errorf("0x%08x", rv)
		}
	}

	_CFRelease(_CFTypeRef(d.extra.file))
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
		return 0, nil, ErrDeviceIsClosed
	}
}

type resultCtx struct {
	len _CFIndex
	err chan error
}

func resultCallback(context unsafe.Pointer, result _IOReturn, sender uintptr, reportType _IOHIDReportType, reportId uint32, report uintptr, reportLength _CFIndex) {
	ctx := (*resultCtx)(context)

	if result != kIOReturnSuccess {
		ctx.len = 0
		ctx.err <- fmt.Errorf("0x%08x", result)
	}

	ctx.len = reportLength
	ctx.err <- nil
}

func (d *Device) setReport(typ _IOHIDReportType, reportId byte, data []byte) error {
	if d.extra.disconnect {
		if err := d.close(); err != nil {
			return err
		}
		return ErrDeviceIsClosed
	}

	ctx := &resultCtx{
		err: make(chan error),
	}
	buf := append([]byte{}, data...)
	if d.reportWithId {
		buf = append([]byte{reportId}, buf...)
	}
	_IOHIDDeviceSetReportWithCallback(d.extra.file, typ, _CFIndex(reportId), buf, _CFIndex(len(buf)), 0, resultCallbackPtr, unsafe.Pointer(ctx))

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
		return nil, ErrDeviceIsClosed
	}

	ctx := &resultCtx{
		err: make(chan error),
	}
	buf := make([]byte, d.reportFeatureLength+1)
	l := _CFIndex(d.reportFeatureLength + 1)
	if rv := _IOHIDDeviceGetReportWithCallback(d.extra.file, kIOHIDReportTypeFeature, _CFIndex(reportId), buf, &l, 0, resultCallbackPtr, unsafe.Pointer(ctx)); rv != kIOReturnSuccess {
		return nil, fmt.Errorf("failed to submit request: 0x%08x", rv)
	}

	if err := <-ctx.err; err != nil {
		return nil, err
	}

	if d.reportWithId {
		return buf[1:ctx.len], nil
	}
	return buf[:ctx.len], nil
}
