// Copyright 2022-2026 Rafael G. Martins. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package usbhid

import (
	"bytes"
	"errors"
	"testing"
	"time"
	"unsafe"
)

func TestDarwinSystemAllocator(t *testing.T) {
	allocator := systemAllocator()
	if allocator == 0 {
		t.Fatal("kCFAllocatorSystemDefault resolved to nil")
	}
	ptr := _CFAllocatorAllocate(allocator, 16, 0)
	if ptr == nil {
		t.Fatal("CFAllocatorAllocate returned nil")
	}
	_CFAllocatorDeallocate(allocator, ptr)
}

func TestDarwinInputCallbackCopiesNativeReport(t *testing.T) {
	d := &Device{}
	d.extra.state = deviceOpen
	d.extra.inputBufferLen = 4
	d.extra.inputCh = make(chan inputCtx, 1)
	handle := registerCallbackDevice(d)
	defer unregisterCallbackDevice(handle)

	report := []byte{3, 1, 2, 3}
	inputCallback(handle, kIOReturnSuccess, 0, 0, 3, unsafe.Pointer(&report[0]), _CFIndex(len(report)))
	report[1] = 9

	result := <-d.extra.inputCh
	if result.err != nil {
		t.Fatalf("unexpected callback error: %v", result.err)
	}
	if !bytes.Equal(result.buf, []byte{3, 1, 2, 3}) {
		t.Fatalf("callback did not copy report: %v", result.buf)
	}
}

func TestDarwinInputCallbackRejectsInvalidLength(t *testing.T) {
	d := &Device{}
	d.extra.state = deviceOpen
	d.extra.inputBufferLen = 1
	d.extra.inputCh = make(chan inputCtx, 1)
	handle := registerCallbackDevice(d)
	defer unregisterCallbackDevice(handle)

	report := []byte{1}
	inputCallback(handle, kIOReturnSuccess, 0, 0, 0, unsafe.Pointer(&report[0]), 2)
	if result := <-d.extra.inputCh; result.err == nil {
		t.Fatal("invalid callback length was accepted")
	}
}

func TestDarwinCloseUnblocksInputReader(t *testing.T) {
	originalClose := _IOHIDDeviceClose
	originalRelease := _CFRelease
	originalPush := _objc_autoreleasePoolPush
	originalPop := _objc_autoreleasePoolPop
	defer func() {
		_IOHIDDeviceClose = originalClose
		_CFRelease = originalRelease
		_objc_autoreleasePoolPush = originalPush
		_objc_autoreleasePoolPop = originalPop
	}()

	_IOHIDDeviceClose = func(_ _IOHIDDeviceRef, _ _IOOptionBits) _IOReturn { return kIOReturnSuccess }
	_CFRelease = func(_ _CFTypeRef) {}
	_objc_autoreleasePoolPush = func() uintptr { return 1 }
	_objc_autoreleasePoolPop = func(_ uintptr) {}

	d := &Device{}
	d.extra.state = deviceOpen
	d.extra.file = 1
	d.extra.inputCh = make(chan inputCtx)
	d.extra.done = make(chan struct{})
	d.extra.runloopDone = make(chan struct{})
	close(d.extra.runloopDone)

	result := make(chan error, 1)
	go func() {
		_, _, err := d.getInputReport()
		result <- err
	}()

	if err := d.close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	select {
	case err := <-result:
		if !errors.Is(err, ErrDeviceIsClosed) {
			t.Fatalf("reader returned %v, want ErrDeviceIsClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("input reader remained blocked after close")
	}
}

func TestDarwinCloseWaitsForSynchronousIOBeforeTeardown(t *testing.T) {
	originalSetReport := _IOHIDDeviceSetReport
	originalSignal := _CFRunLoopSourceSignal
	originalClose := _IOHIDDeviceClose
	originalRelease := _CFRelease
	originalPush := _objc_autoreleasePoolPush
	originalPop := _objc_autoreleasePoolPop
	defer func() {
		_IOHIDDeviceSetReport = originalSetReport
		_CFRunLoopSourceSignal = originalSignal
		_IOHIDDeviceClose = originalClose
		_CFRelease = originalRelease
		_objc_autoreleasePoolPush = originalPush
		_objc_autoreleasePoolPop = originalPop
	}()

	ioStarted := make(chan struct{})
	allowIO := make(chan struct{})
	teardownStarted := make(chan struct{}, 1)
	_IOHIDDeviceSetReport = func(_ _IOHIDDeviceRef, _ _IOHIDReportType, _ _CFIndex, _ []byte, _ _CFIndex) _IOReturn {
		close(ioStarted)
		<-allowIO
		return kIOReturnSuccess
	}
	_CFRunLoopSourceSignal = func(_ _CFRunLoopSourceRef) { teardownStarted <- struct{}{} }
	_IOHIDDeviceClose = func(_ _IOHIDDeviceRef, _ _IOOptionBits) _IOReturn { return kIOReturnSuccess }
	_CFRelease = func(_ _CFTypeRef) {}
	_objc_autoreleasePoolPush = func() uintptr { return 1 }
	_objc_autoreleasePoolPop = func(_ uintptr) {}

	d := &Device{}
	d.extra.state = deviceOpen
	d.extra.file = 1
	d.extra.ioSource = 1
	d.extra.done = make(chan struct{})
	d.extra.runloopDone = make(chan struct{})
	close(d.extra.runloopDone)

	ioResult := make(chan error, 1)
	go func() { ioResult <- d.setFeatureReport(0, []byte{1}) }()
	<-ioStarted

	closeResult := make(chan error, 1)
	go func() { closeResult <- d.close() }()
	deadline := time.After(time.Second)
	for {
		d.extra.stateMtx.Lock()
		state := d.extra.state
		d.extra.stateMtx.Unlock()
		if state == deviceClosing {
			break
		}
		select {
		case <-deadline:
			t.Fatal("close did not enter closing state")
		default:
		}
	}

	select {
	case <-teardownStarted:
		t.Fatal("run-loop teardown started while synchronous I/O was active")
	case <-time.After(50 * time.Millisecond):
	}

	close(allowIO)
	if err := <-ioResult; err != nil {
		t.Fatalf("synchronous I/O failed: %v", err)
	}
	select {
	case <-teardownStarted:
	case <-time.After(time.Second):
		t.Fatal("run-loop teardown did not start after synchronous I/O completed")
	}
	if err := <-closeResult; err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

func TestDarwinRemovalDuringSynchronousIODefersRelease(t *testing.T) {
	originalSetReport := _IOHIDDeviceSetReport
	originalClose := _IOHIDDeviceClose
	originalRelease := _CFRelease
	originalPush := _objc_autoreleasePoolPush
	originalPop := _objc_autoreleasePoolPop
	defer func() {
		_IOHIDDeviceSetReport = originalSetReport
		_IOHIDDeviceClose = originalClose
		_CFRelease = originalRelease
		_objc_autoreleasePoolPush = originalPush
		_objc_autoreleasePoolPop = originalPop
	}()

	ioStarted := make(chan struct{})
	allowIO := make(chan struct{})
	released := make(chan struct{}, 1)
	_IOHIDDeviceSetReport = func(_ _IOHIDDeviceRef, _ _IOHIDReportType, _ _CFIndex, _ []byte, _ _CFIndex) _IOReturn {
		close(ioStarted)
		<-allowIO
		return kIOReturnSuccess
	}
	_IOHIDDeviceClose = func(_ _IOHIDDeviceRef, _ _IOOptionBits) _IOReturn { return kIOReturnSuccess }
	_CFRelease = func(_ _CFTypeRef) { released <- struct{}{} }
	_objc_autoreleasePoolPush = func() uintptr { return 1 }
	_objc_autoreleasePoolPop = func(_ uintptr) {}

	d := &Device{}
	d.extra.state = deviceOpen
	d.extra.file = 1
	d.extra.done = make(chan struct{})
	d.extra.runloopDone = make(chan struct{})
	close(d.extra.runloopDone)
	handle := registerCallbackDevice(d)
	d.extra.callbackHandle = handle

	ioResult := make(chan error, 1)
	go func() { ioResult <- d.setFeatureReport(0, []byte{1}) }()
	<-ioStarted

	removalCallback(handle, kIOReturnSuccess, 0)
	// A duplicate native removal notification must not close done twice.
	removalCallback(handle, kIOReturnSuccess, 0)
	select {
	case <-d.extra.done:
	case <-time.After(time.Second):
		t.Fatal("removal did not close the session channel")
	}
	select {
	case <-released:
		t.Fatal("device was released while synchronous I/O was active")
	case <-time.After(50 * time.Millisecond):
	}

	close(allowIO)
	if err := <-ioResult; err != nil {
		t.Fatalf("synchronous I/O failed: %v", err)
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("device was not released after synchronous I/O completed")
	}
	deadline := time.After(time.Second)
	for {
		d.extra.stateMtx.Lock()
		state := d.extra.state
		d.extra.stateMtx.Unlock()
		if state == deviceClosed {
			break
		}
		select {
		case <-deadline:
			t.Fatal("automatic close did not complete")
		default:
		}
	}
}

func TestDarwinFinishOpenRejectsRemovalRace(t *testing.T) {
	d := &Device{}
	d.extra.state = deviceDisconnected

	if err := d.finishOpen(); !errors.Is(err, ErrDeviceIsClosed) {
		t.Fatalf("finishOpen returned %v, want ErrDeviceIsClosed", err)
	}
	if d.extra.state != deviceDisconnected {
		t.Fatalf("finishOpen changed disconnected state to %v", d.extra.state)
	}
}

func TestDarwinFinishOpenPublishesOpenState(t *testing.T) {
	d := &Device{}
	d.extra.state = deviceOpening

	if err := d.finishOpen(); err != nil {
		t.Fatalf("finishOpen failed: %v", err)
	}
	if d.extra.state != deviceOpen {
		t.Fatalf("finishOpen left state at %v", d.extra.state)
	}
}

func TestDarwinSynchronousReportFraming(t *testing.T) {
	originalSetReport := _IOHIDDeviceSetReport
	originalPush := _objc_autoreleasePoolPush
	originalPop := _objc_autoreleasePoolPop
	defer func() {
		_IOHIDDeviceSetReport = originalSetReport
		_objc_autoreleasePoolPush = originalPush
		_objc_autoreleasePoolPop = originalPop
	}()

	_objc_autoreleasePoolPush = func() uintptr { return 1 }
	_objc_autoreleasePoolPop = func(_ uintptr) {}

	var got []byte
	_IOHIDDeviceSetReport = func(_ _IOHIDDeviceRef, _ _IOHIDReportType, _ _CFIndex, report []byte, _ _CFIndex) _IOReturn {
		got = append([]byte{}, report...)
		return kIOReturnSuccess
	}

	d := &Device{reportWithId: true}
	d.extra.state = deviceOpen
	d.extra.file = 1
	if err := d.setFeatureReport(7, []byte{1, 2}); err != nil {
		t.Fatalf("set feature report failed: %v", err)
	}
	if !bytes.Equal(got, []byte{7, 1, 2}) {
		t.Fatalf("report framing mismatch: %v", got)
	}
}

func TestDarwinSynchronousFeatureReportUsesReturnedLength(t *testing.T) {
	originalGetReport := _IOHIDDeviceGetReport
	originalPush := _objc_autoreleasePoolPush
	originalPop := _objc_autoreleasePoolPop
	defer func() {
		_IOHIDDeviceGetReport = originalGetReport
		_objc_autoreleasePoolPush = originalPush
		_objc_autoreleasePoolPop = originalPop
	}()

	_objc_autoreleasePoolPush = func() uintptr { return 1 }
	_objc_autoreleasePoolPop = func(_ uintptr) {}
	_IOHIDDeviceGetReport = func(_ _IOHIDDeviceRef, _ _IOHIDReportType, _ _CFIndex, report []byte, length *_CFIndex) _IOReturn {
		copy(report, []byte{4, 8, 9})
		*length = 3
		return kIOReturnSuccess
	}

	d := &Device{reportFeatureLength: 8, reportWithId: true}
	d.extra.state = deviceOpen
	d.extra.file = 1
	report, err := d.getFeatureReport(4)
	if err != nil {
		t.Fatalf("get feature report failed: %v", err)
	}
	if !bytes.Equal(report, []byte{8, 9}) {
		t.Fatalf("feature report length mismatch: %v", report)
	}
}
