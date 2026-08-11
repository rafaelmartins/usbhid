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
	_CFRunLoopRef       uintptr
	_CFRunLoopSourceRef uintptr
	_CFSetRef           uintptr
	_CFStringEncoding   uint32
	_CFStringRef        uintptr
	_CFTimeInterval     float64
	_CFTypeRef          uintptr
)

type _CFRunLoopSourceContext struct {
	version         _CFIndex
	info            uintptr
	retain          uintptr
	release         uintptr
	copyDescription uintptr
	equal           uintptr
	hash            uintptr
	schedule        uintptr
	cancel          uintptr
	perform         uintptr
}

type (
	_IOHIDDeviceRef  uintptr
	_IOHIDManagerRef uintptr
	_IOHIDReportType uint32
	_IOOptionBits    uint32
	_IOReturn        = _kern_return_t
)

type deviceExtra struct {
	// serializes complete open/close transitions.
	lifeMtx sync.Mutex
	// protects the fields observed by callbacks and public operations.
	stateMtx sync.Mutex
	// i/o calls hold while entering iokit.
	ioMtx sync.Mutex

	state   deviceState
	file    _IOHIDDeviceRef
	options _IOOptionBits

	runloop     _CFRunLoopRef
	runloopDone chan struct{}
	ioSource    _CFRunLoopSourceRef
	ioCh        chan func()
	reportCh    chan _IOReturn

	done chan struct{}

	inputBuffer    unsafe.Pointer
	inputBufferLen _CFIndex
	inputCh        chan inputCtx
	inputClosed    bool
	callbackHandle uintptr
}

type deviceState uint8

const (
	deviceClosed deviceState = iota
	deviceOpening
	deviceOpen
	deviceClosing
	deviceDisconnected
	deviceRunloopFailed
)

const (
	kCFAllocatorDefault _CFAllocatorRef = 0

	kCFNumberSInt16Type _CFIndex = 2

	kCFStringEncodingUTF8 _CFStringEncoding = 0x08000100

	kCFRunLoopRunFinished int32 = 1
	kCFRunLoopRunStopped  int32 = 2
)

var (
	_mach_error_string func(errorValue _kern_return_t) string

	_CFAllocatorAllocate     func(allocator _CFAllocatorRef, size _CFIndex, hint uintptr) unsafe.Pointer
	_CFAllocatorDeallocate   func(allocator _CFAllocatorRef, ptr unsafe.Pointer)
	_CFDataGetBytes          func(data _CFDataRef, rang _CFRange, buffer []byte)
	_CFDataGetLength         func(data _CFDataRef) _CFIndex
	_CFNumberGetValue        func(number _CFNumberRef, theType _CFNumberType, valuePtr unsafe.Pointer) bool
	_CFRelease               func(cf _CFTypeRef)
	_CFRunLoopGetCurrent     func() _CFRunLoopRef
	_CFRunLoopRunInMode      func(mode _CFStringRef, seconds _CFTimeInterval, returnAfterSourceHandled bool) int32
	_CFRunLoopStop           func(runLoop _CFRunLoopRef)
	_CFRunLoopSourceCreate   func(allocator _CFAllocatorRef, order _CFIndex, context *_CFRunLoopSourceContext) _CFRunLoopSourceRef
	_CFRunLoopAddSource      func(runLoop _CFRunLoopRef, source _CFRunLoopSourceRef, mode _CFStringRef)
	_CFRunLoopRemoveSource   func(runLoop _CFRunLoopRef, source _CFRunLoopSourceRef, mode _CFStringRef)
	_CFRunLoopSourceSignal   func(source _CFRunLoopSourceRef)
	_CFRunLoopWakeUp         func(runLoop _CFRunLoopRef)
	_CFSetGetCount           func(theSet _CFSetRef) _CFIndex
	_CFSetGetValues          func(theSet _CFSetRef, value unsafe.Pointer)
	_CFStringCreateWithBytes func(alloc _CFAllocatorRef, bytes []byte, numBytes _CFIndex, encoding _CFStringEncoding, isExternalRepresentation bool) _CFStringRef
	_CFStringGetCString      func(theString _CFStringRef, buffer []byte, encoding _CFStringEncoding) bool
	_CFStringGetLength       func(theString _CFStringRef) _CFIndex

	_objc_autoreleasePoolPush func() uintptr
	_objc_autoreleasePoolPop  func(pool uintptr)
)

var (
	_kCFAllocatorSystemDefault uintptr
	_kCFRunLoopDefaultMode     uintptr
)

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
	_IOHIDDeviceGetReport                   func(device _IOHIDDeviceRef, reportType _IOHIDReportType, reportId _CFIndex, report []byte, pReportLength *_CFIndex) _IOReturn
	_IOHIDDeviceGetService                  func(device _IOHIDDeviceRef) _io_service_t
	_IOHIDDeviceOpen                        func(device _IOHIDDeviceRef, options _IOOptionBits) _IOReturn
	_IOHIDDeviceRegisterInputReportCallback func(device _IOHIDDeviceRef, report unsafe.Pointer, reportLength _CFIndex, callback uintptr, context uintptr)
	_IOHIDDeviceRegisterRemovalCallback     func(device _IOHIDDeviceRef, callback uintptr, context uintptr)
	_IOHIDDeviceScheduleWithRunLoop         func(device _IOHIDDeviceRef, runLoop _CFRunLoopRef, runLoopMode _CFStringRef)
	_IOHIDDeviceSetReportWithCallback       func(device _IOHIDDeviceRef, reportType _IOHIDReportType, reportID _CFIndex, report unsafe.Pointer, reportLength _CFIndex, timeout _CFTimeInterval, callback uintptr, context uintptr) _IOReturn
	_IOHIDDeviceUnscheduleFromRunLoop       func(device _IOHIDDeviceRef, runLoop _CFRunLoopRef, runLoopMode _CFStringRef)
	_IOHIDManagerCopyDevices                func(manager _IOHIDManagerRef) _CFSetRef
	_IOHIDManagerCreate                     func(allocator _CFAllocatorRef, options _IOOptionBits) _IOHIDManagerRef
	_IOHIDManagerSetDeviceMatching          func(manager _IOHIDManagerRef, matching _CFDictionaryRef)
	_IOObjectRelease                        func(object _io_object_t) _kern_return_t
	_IORegistryEntryGetPath                 func(entry _io_registry_entry_t, plane _io_name_t, path _io_string_t) _kern_return_t
	_IORegistryEntryGetRegistryEntryID      func(entry _io_registry_entry_t, entryID *uint64) _kern_return_t
	_IORegistryEntryFromPath                func(mainPort _mach_port_t, path _io_string_t) _io_registry_entry_t
)

var (
	mgrMtx sync.Mutex
	mgr    _IOHIDManagerRef

	inputCallbackPtr         = purego.NewCallback(inputCallback)
	removalCallbackPtr       = purego.NewCallback(removalCallback)
	reportCallbackPtr        = purego.NewCallback(reportCallback)
	sourcePerformCallbackPtr = purego.NewCallback(sourcePerformCallback)
)

var callbackDevices = struct {
	sync.RWMutex
	next    uintptr
	devices map[uintptr]*Device
}{
	next:    1,
	devices: map[uintptr]*Device{},
}

func init() {
	purego.RegisterLibFunc(&_mach_error_string, purego.RTLD_DEFAULT, "mach_error_string")

	cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		panic(err)
	}

	purego.RegisterLibFunc(&_CFAllocatorAllocate, cf, "CFAllocatorAllocate")
	purego.RegisterLibFunc(&_CFAllocatorDeallocate, cf, "CFAllocatorDeallocate")
	purego.RegisterLibFunc(&_CFDataGetBytes, cf, "CFDataGetBytes")
	purego.RegisterLibFunc(&_CFDataGetLength, cf, "CFDataGetLength")
	purego.RegisterLibFunc(&_CFNumberGetValue, cf, "CFNumberGetValue")
	purego.RegisterLibFunc(&_CFRelease, cf, "CFRelease")
	purego.RegisterLibFunc(&_CFRunLoopGetCurrent, cf, "CFRunLoopGetCurrent")
	purego.RegisterLibFunc(&_CFRunLoopRunInMode, cf, "CFRunLoopRunInMode")
	purego.RegisterLibFunc(&_CFRunLoopStop, cf, "CFRunLoopStop")
	purego.RegisterLibFunc(&_CFRunLoopSourceCreate, cf, "CFRunLoopSourceCreate")
	purego.RegisterLibFunc(&_CFRunLoopAddSource, cf, "CFRunLoopAddSource")
	purego.RegisterLibFunc(&_CFRunLoopRemoveSource, cf, "CFRunLoopRemoveSource")
	purego.RegisterLibFunc(&_CFRunLoopSourceSignal, cf, "CFRunLoopSourceSignal")
	purego.RegisterLibFunc(&_CFRunLoopWakeUp, cf, "CFRunLoopWakeUp")
	purego.RegisterLibFunc(&_CFSetGetCount, cf, "CFSetGetCount")
	purego.RegisterLibFunc(&_CFSetGetValues, cf, "CFSetGetValues")
	purego.RegisterLibFunc(&_CFStringCreateWithBytes, cf, "CFStringCreateWithBytes")
	purego.RegisterLibFunc(&_CFStringGetCString, cf, "CFStringGetCString")
	purego.RegisterLibFunc(&_CFStringGetLength, cf, "CFStringGetLength")

	_kCFRunLoopDefaultMode, err = purego.Dlsym(cf, "kCFRunLoopDefaultMode")
	if err != nil {
		panic(err)
	}
	_kCFAllocatorSystemDefault, err = purego.Dlsym(cf, "kCFAllocatorSystemDefault")
	if err != nil {
		panic(err)
	}

	objc, err := purego.Dlopen("/usr/lib/libobjc.A.dylib", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		panic(err)
	}

	purego.RegisterLibFunc(&_objc_autoreleasePoolPush, objc, "objc_autoreleasePoolPush")
	purego.RegisterLibFunc(&_objc_autoreleasePoolPop, objc, "objc_autoreleasePoolPop")

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
	purego.RegisterLibFunc(&_IOHIDDeviceSetReportWithCallback, iokit, "IOHIDDeviceSetReportWithCallback")
	purego.RegisterLibFunc(&_IOHIDDeviceUnscheduleFromRunLoop, iokit, "IOHIDDeviceUnscheduleFromRunLoop")
	purego.RegisterLibFunc(&_IOHIDManagerCopyDevices, iokit, "IOHIDManagerCopyDevices")
	purego.RegisterLibFunc(&_IOHIDManagerCreate, iokit, "IOHIDManagerCreate")
	purego.RegisterLibFunc(&_IOHIDManagerSetDeviceMatching, iokit, "IOHIDManagerSetDeviceMatching")
	purego.RegisterLibFunc(&_IOObjectRelease, iokit, "IOObjectRelease")
	purego.RegisterLibFunc(&_IORegistryEntryGetPath, iokit, "IORegistryEntryGetPath")
	purego.RegisterLibFunc(&_IORegistryEntryGetRegistryEntryID, iokit, "IORegistryEntryGetRegistryEntryID")
	purego.RegisterLibFunc(&_IORegistryEntryFromPath, iokit, "IORegistryEntryFromPath")

	mgr = _IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone)
	if mgr == 0 {
		panic("failed to create iohid manager")
	}
}

type ioReturnError _IOReturn

func (e ioReturnError) Error() string {
	return fmt.Sprintf("%s (0x%08x)", _mach_error_string(_IOReturn(e)), uint32(e))
}

func byteSliceToString(b []byte) string {
	if before, _, ok := bytes.Cut(b, []byte{0}); ok {
		return string(before)
	}
	return string(b)
}

func cfstringToString(str _CFStringRef) (string, error) {
	buf := make([]byte, _CFStringGetLength(str)*4+1)
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
	mgrMtx.Lock()
	defer mgrMtx.Unlock()

	// IOHIDManagerCopyDevices instantiates HID device wrapper objects that
	// are autoreleased on the calling thread. Pin the goroutine to its OS
	// thread (pools are thread-local) and drain the pool when done, so
	// repeated enumeration doesn't accumulate them indefinitely.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pool := _objc_autoreleasePoolPush()
	defer _objc_autoreleasePoolPop(pool)

	_IOHIDManagerSetDeviceMatching(mgr, 0)

	rv := []*Device{}

	device_set := _IOHIDManagerCopyDevices(mgr)
	if device_set == 0 {
		return rv, nil
	}
	defer _CFRelease(_CFTypeRef(device_set))

	count := _CFSetGetCount(device_set)
	if count == 0 {
		return rv, nil
	}

	devices := make([]_IOHIDDeviceRef, count)
	_CFSetGetValues(device_set, unsafe.Pointer(&devices[0]))

	bIOService := make([]byte, 128)
	copy(bIOService[:], "IOService")

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
			path:  path,
			extra: deviceExtra{state: deviceClosed},
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

func inputCallback(context uintptr, result _IOReturn, sender uintptr, reportType _IOHIDReportType, reportId uint32, report unsafe.Pointer, reportLength _CFIndex) {
	d := deviceFromCallbackContext(context)
	if d == nil {
		return
	}

	d.extra.stateMtx.Lock()
	defer d.extra.stateMtx.Unlock()

	if d.extra.inputClosed {
		return
	}

	ctx := inputCtx{}
	if result != kIOReturnSuccess {
		ctx.err = ioReturnError(result)
	} else if report == nil {
		ctx.err = errors.New("report buffer is nil")
	} else if reportLength < 0 || reportLength > d.extra.inputBufferLen {
		ctx.err = fmt.Errorf("invalid report length: %d", reportLength)
	} else {
		ctx.buf = append([]byte{}, unsafe.Slice((*byte)(report), int(reportLength))...)
	}

	select {
	case d.extra.inputCh <- ctx:
	default:
	}
}

func removalCallback(context uintptr, result _IOReturn, sender uintptr) {
	d := deviceFromCallbackContext(context)
	if d == nil {
		return
	}

	d.extra.stateMtx.Lock()
	if d.extra.state != deviceOpening && d.extra.state != deviceOpen {
		d.extra.stateMtx.Unlock()
		return
	}
	d.extra.state = deviceDisconnected
	d.extra.inputClosed = true
	close(d.extra.done)
	d.extra.stateMtx.Unlock()

	go func() {
		// close waits for any asynchronous report completion before stopping
		// the run loop. stopping it in this callback could prevent that
		// completion from being delivered and deadlock close on ioMtx.
		d.close()
	}()
}

func reportCallback(context uintptr, result _IOReturn, sender uintptr, reportType _IOHIDReportType, reportId uint32, report unsafe.Pointer, reportLength _CFIndex) {
	d := deviceFromCallbackContext(context)
	if d == nil {
		return
	}

	d.extra.stateMtx.Lock()
	reportCh := d.extra.reportCh
	d.extra.stateMtx.Unlock()
	if reportCh == nil {
		return
	}

	select {
	case reportCh <- result:
	default:
	}
}

func sourcePerformCallback(context uintptr) {
	d := deviceFromCallbackContext(context)
	if d == nil {
		return
	}

	d.extra.stateMtx.Lock()
	ioCh := d.extra.ioCh
	runloop := d.extra.runloop
	d.extra.stateMtx.Unlock()

	select {
	case fn := <-ioCh:
		fn()
		return
	default:
	}

	if runloop != 0 {
		_CFRunLoopStop(runloop)
	}
}

func deviceFromCallbackContext(context uintptr) *Device {
	if context == 0 {
		return nil
	}

	callbackDevices.RLock()
	defer callbackDevices.RUnlock()
	return callbackDevices.devices[context]
}

func registerCallbackDevice(d *Device) uintptr {
	callbackDevices.Lock()
	defer callbackDevices.Unlock()

	handle := callbackDevices.next
	callbackDevices.next++
	if callbackDevices.next == 0 {
		callbackDevices.next = 1
	}
	callbackDevices.devices[handle] = d
	return handle
}

func unregisterCallbackDevice(handle uintptr) {
	if handle == 0 {
		return
	}

	callbackDevices.Lock()
	delete(callbackDevices.devices, handle)
	callbackDevices.Unlock()
}

func defaultRunLoopMode() _CFStringRef {
	return **(**_CFStringRef)(unsafe.Pointer(&_kCFRunLoopDefaultMode))
}

func systemAllocator() _CFAllocatorRef {
	return **(**_CFAllocatorRef)(unsafe.Pointer(&_kCFAllocatorSystemDefault))
}

func (d *Device) open(lock bool) (err error) {
	d.extra.lifeMtx.Lock()
	defer d.extra.lifeMtx.Unlock()
	sessionPublished := false

	d.extra.stateMtx.Lock()
	if d.extra.state != deviceClosed {
		d.extra.stateMtx.Unlock()
		return ErrDeviceIsOpen
	}
	d.extra.state = deviceOpening
	d.extra.stateMtx.Unlock()

	defer func() {
		if err != nil && !sessionPublished {
			d.extra.stateMtx.Lock()
			d.extra.state = deviceClosed
			d.extra.stateMtx.Unlock()
		}
	}()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pool := _objc_autoreleasePoolPush()
	defer _objc_autoreleasePoolPop(pool)

	options := kIOHIDOptionsTypeNone
	if lock {
		options = kIOHIDOptionsTypeSeizeDevice
	}

	pathB := make([]byte, 512)
	copy(pathB[:], d.path)
	entry := _IORegistryEntryFromPath(0, pathB)
	if entry == 0 {
		return errors.New("failed to lookup io registry entry from path")
	}
	defer _IOObjectRelease(entry)

	file := _IOHIDDeviceCreate(kCFAllocatorDefault, entry)
	if file == 0 {
		return errors.New("failed to create iohid device")
	}

	if rv := _IOHIDDeviceOpen(file, options); rv != kIOReturnSuccess {
		_CFRelease(_CFTypeRef(file))
		if rv == kIOReturnExclusiveAccess {
			return ErrDeviceLocked
		}
		return ioReturnError(rv)
	}

	inputBufferLen := _CFIndex(d.reportInputLength + 1)
	inputBuffer := _CFAllocatorAllocate(systemAllocator(), inputBufferLen, 0)
	if inputBuffer == nil {
		_IOHIDDeviceClose(file, options)
		_CFRelease(_CFTypeRef(file))
		return errors.New("failed to allocate input report buffer")
	}
	inputBytes := unsafe.Slice((*byte)(inputBuffer), int(inputBufferLen))
	for i := range inputBytes {
		inputBytes[i] = 0
	}

	callbackHandle := registerCallbackDevice(d)
	callbackContext := callbackHandle
	ioSource := _CFRunLoopSourceCreate(kCFAllocatorDefault, 0, &_CFRunLoopSourceContext{
		version: 0,
		info:    callbackContext,
		perform: sourcePerformCallbackPtr,
	})
	if ioSource == 0 {
		unregisterCallbackDevice(callbackHandle)
		_CFAllocatorDeallocate(systemAllocator(), inputBuffer)
		_IOHIDDeviceClose(file, options)
		_CFRelease(_CFTypeRef(file))
		return errors.New("failed to create run loop source")
	}

	inputCh := make(chan inputCtx)
	done := make(chan struct{})
	runloopDone := make(chan struct{})
	ioCh := make(chan func(), 1)
	reportCh := make(chan _IOReturn, 1)
	ready := make(chan struct{})

	d.extra.stateMtx.Lock()
	d.extra.file = file
	d.extra.options = options
	d.extra.runloop = 0
	d.extra.runloopDone = runloopDone
	d.extra.ioSource = ioSource
	d.extra.ioCh = ioCh
	d.extra.reportCh = reportCh
	d.extra.done = done
	d.extra.inputBuffer = inputBuffer
	d.extra.inputBufferLen = inputBufferLen
	d.extra.inputCh = inputCh
	d.extra.inputClosed = false
	d.extra.callbackHandle = callbackHandle
	d.extra.stateMtx.Unlock()
	sessionPublished = true

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		runloop := _CFRunLoopGetCurrent()
		mode := defaultRunLoopMode()
		pool := _objc_autoreleasePoolPush()
		_IOHIDDeviceScheduleWithRunLoop(file, runloop, mode)
		_IOHIDDeviceRegisterInputReportCallback(file, inputBuffer, inputBufferLen, inputCallbackPtr, callbackContext)
		_IOHIDDeviceRegisterRemovalCallback(file, removalCallbackPtr, callbackContext)
		_CFRunLoopAddSource(runloop, ioSource, mode)
		_objc_autoreleasePoolPop(pool)

		d.extra.stateMtx.Lock()
		d.extra.runloop = runloop
		d.extra.stateMtx.Unlock()
		close(ready)

		// Run the loop in bounded slices, draining the Objective-C
		// autorelease pool between them. IOHIDLib autoreleases objects on
		// every report callback, and this Go-created thread never pops a
		// pool on its own (that is normally done by AppKit machinery), so
		// with a bare CFRunLoopRun those objects would accumulate for the
		// life of the thread and grow the process footprint without bound.
		for {
			select {
			case <-done:
				goto stopped
			default:
			}

			pool = _objc_autoreleasePoolPush()
			rv := _CFRunLoopRunInMode(mode, 60, false)
			_objc_autoreleasePoolPop(pool)
			if rv == kCFRunLoopRunFinished || rv == kCFRunLoopRunStopped {
				break
			}
		}

	stopped:
		d.extra.stateMtx.Lock()
		disconnected := d.extra.state == deviceDisconnected
		unexpectedStop := d.extra.state == deviceOpen || d.extra.state == deviceOpening
		if unexpectedStop {
			d.extra.state = deviceRunloopFailed
			close(d.extra.done)
		}
		d.extra.inputClosed = true
		d.extra.stateMtx.Unlock()
		if unexpectedStop {
			// unexpected run-loop exit has no Close caller holding ioMtx.
			// exclude report I/O before touching the IOHID device.
			d.extra.ioMtx.Lock()
		}

		pool = _objc_autoreleasePoolPush()
		if !disconnected {
			_IOHIDDeviceRegisterInputReportCallback(file, inputBuffer, inputBufferLen, 0, 0)
			_IOHIDDeviceRegisterRemovalCallback(file, 0, 0)
			_IOHIDDeviceUnscheduleFromRunLoop(file, runloop, mode)
		}
		_CFRunLoopRemoveSource(runloop, ioSource, mode)
		_objc_autoreleasePoolPop(pool)
		close(runloopDone)
		if unexpectedStop {
			d.extra.ioMtx.Unlock()
			go func() {
				d.close()
			}()
		}
	}()

	<-ready

	return d.finishOpen()
}

func (d *Device) finishOpen() error {
	d.extra.stateMtx.Lock()
	defer d.extra.stateMtx.Unlock()

	if d.extra.state != deviceOpening {
		return ErrDeviceIsClosed
	}
	d.extra.state = deviceOpen
	return nil
}

func (d *Device) isOpen() bool {
	d.extra.stateMtx.Lock()
	defer d.extra.stateMtx.Unlock()
	return d.extra.state != deviceClosed
}

func (d *Device) close() error {
	d.extra.lifeMtx.Lock()
	defer d.extra.lifeMtx.Unlock()

	d.extra.stateMtx.Lock()
	if d.extra.state == deviceClosed {
		d.extra.stateMtx.Unlock()
		return nil
	}

	disconnected := d.extra.state == deviceDisconnected
	runloopFailed := d.extra.state == deviceRunloopFailed
	doneClosed := disconnected || runloopFailed || d.extra.state == deviceClosing
	if !doneClosed {
		d.extra.state = deviceClosing
		close(d.extra.done)
	}
	d.extra.inputClosed = true
	file := d.extra.file
	options := d.extra.options
	runloop := d.extra.runloop
	runloopDone := d.extra.runloopDone
	ioSource := d.extra.ioSource
	inputBuffer := d.extra.inputBuffer
	callbackHandle := d.extra.callbackHandle
	d.extra.stateMtx.Unlock()

	if !runloopFailed {
		// closing state prevents new operations from starting. taking ioMtx here
		// lets an already-running report operation finish before the run-loop
		// thread unregisters or unschedules the same IOHIDDeviceRef.
		d.extra.ioMtx.Lock()
	}

	if ioSource != 0 {
		_CFRunLoopSourceSignal(ioSource)
	}
	if runloop != 0 {
		_CFRunLoopWakeUp(runloop)
		_CFRunLoopStop(runloop)
	}
	if runloopDone != nil {
		<-runloopDone
	}
	if runloopFailed {
		// unexpected run-loop teardown owns ioMtx until runloopDone is closed.
		d.extra.ioMtx.Lock()
	}
	defer d.extra.ioMtx.Unlock()

	var closeErr error
	runtime.LockOSThread()
	pool := _objc_autoreleasePoolPush()
	if !disconnected {
		if rv := _IOHIDDeviceClose(file, options); rv != kIOReturnSuccess {
			closeErr = ioReturnError(rv)
		}
	}
	_CFRelease(_CFTypeRef(file))
	_objc_autoreleasePoolPop(pool)
	runtime.UnlockOSThread()

	if ioSource != 0 {
		_CFRelease(_CFTypeRef(ioSource))
	}
	if inputBuffer != nil {
		_CFAllocatorDeallocate(systemAllocator(), inputBuffer)
	}
	if callbackHandle != 0 {
		unregisterCallbackDevice(callbackHandle)
	}

	d.extra.stateMtx.Lock()
	d.extra.file = 0
	d.extra.options = kIOHIDOptionsTypeNone
	d.extra.runloop = 0
	d.extra.runloopDone = nil
	d.extra.ioSource = 0
	d.extra.ioCh = nil
	d.extra.reportCh = nil
	d.extra.inputBuffer = nil
	d.extra.inputBufferLen = 0
	d.extra.callbackHandle = 0
	d.extra.state = deviceClosed
	d.extra.stateMtx.Unlock()

	return closeErr
}

func (d *Device) getInputReport() (byte, []byte, error) {
	d.extra.stateMtx.Lock()
	if d.extra.state != deviceOpen {
		d.extra.stateMtx.Unlock()
		return 0, nil, ErrDeviceIsClosed
	}

	inputCh := d.extra.inputCh
	done := d.extra.done
	d.extra.stateMtx.Unlock()

	select {
	case result := <-inputCh:
		if result.err != nil {
			return 0, nil, result.err
		}

		if d.reportWithId && len(result.buf) > 0 {
			return result.buf[0], result.buf[1:], nil
		}
		return 0, result.buf[:], nil

	case <-done:
		return 0, nil, ErrDeviceIsClosed
	}
}

func (d *Device) setReport(typ _IOHIDReportType, reportId byte, data []byte) error {
	d.extra.ioMtx.Lock()
	defer d.extra.ioMtx.Unlock()

	d.extra.stateMtx.Lock()
	if d.extra.state != deviceOpen {
		d.extra.stateMtx.Unlock()
		return ErrDeviceIsClosed
	}
	file := d.extra.file
	runloop := d.extra.runloop
	ioSource := d.extra.ioSource
	ioCh := d.extra.ioCh
	reportCh := d.extra.reportCh
	callbackHandle := d.extra.callbackHandle
	d.extra.stateMtx.Unlock()

	buf := append([]byte{}, data...)
	if d.reportWithId {
		buf = append([]byte{reportId}, buf...)
	}

	allocationLen := _CFIndex(len(buf))
	if allocationLen == 0 {
		allocationLen = 1
	}
	report := _CFAllocatorAllocate(systemAllocator(), allocationLen, 0)
	if report == nil {
		return errors.New("failed to allocate report buffer")
	}
	defer _CFAllocatorDeallocate(systemAllocator(), report)
	copy(unsafe.Slice((*byte)(report), int(allocationLen)), buf)

	// ioMtx permits only one report operation at a time, so any value left
	// here would belong to an operation that violated IOKit's callback
	// contract. discard it rather than associating it with this report.
	select {
	case <-reportCh:
	default:
	}

	ioCh <- func() {
		rv := _IOHIDDeviceSetReportWithCallback(file, typ, _CFIndex(reportId), report, _CFIndex(len(buf)), 0, reportCallbackPtr, callbackHandle)
		if rv != kIOReturnSuccess {
			select {
			case reportCh <- rv:
			default:
			}
		}
	}
	_CFRunLoopSourceSignal(ioSource)
	_CFRunLoopWakeUp(runloop)

	result := <-reportCh
	if result != kIOReturnSuccess {
		return ioReturnError(result)
	}
	return nil
}

func (d *Device) setOutputReport(reportId byte, data []byte) error {
	return d.setReport(kIOHIDReportTypeOutput, reportId, data)
}

func (d *Device) setFeatureReport(reportId byte, data []byte) error {
	return d.setReport(kIOHIDReportTypeFeature, reportId, data)
}

func (d *Device) getFeatureReport(reportId byte) ([]byte, error) {
	d.extra.ioMtx.Lock()
	defer d.extra.ioMtx.Unlock()

	d.extra.stateMtx.Lock()
	if d.extra.state != deviceOpen {
		d.extra.stateMtx.Unlock()
		return nil, ErrDeviceIsClosed
	}
	file := d.extra.file
	d.extra.stateMtx.Unlock()

	buf := make([]byte, d.reportFeatureLength+1)
	if d.reportWithId {
		buf[0] = reportId
	}
	l := _CFIndex(d.reportFeatureLength + 1)

	runtime.LockOSThread()
	pool := _objc_autoreleasePoolPush()
	rv := _IOHIDDeviceGetReport(file, kIOHIDReportTypeFeature, _CFIndex(reportId), buf, &l)
	_objc_autoreleasePoolPop(pool)
	runtime.UnlockOSThread()
	if rv != kIOReturnSuccess {
		return nil, ioReturnError(rv)
	}
	if l < 0 || l > _CFIndex(len(buf)) {
		return nil, fmt.Errorf("invalid report length: %d", l)
	}

	if d.reportWithId {
		return buf[1:l], nil
	}
	return buf[:l], nil
}
