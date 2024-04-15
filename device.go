// Copyright 2022-2023 Rafael G. Martins. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package usbhid provides support for interacting with USB HID
// devices connected to a computer, from userspace.
//
// It is written in pure Go and works on Linux and Windows.
package usbhid

import (
	"errors"
	"fmt"
	"os"
)

// Errors returned from usbhid package may be tested against these errors
// with errors.Is.
var (
	ErrDeviceIsOpen           = errors.New("device is open")
	ErrDeviceIsNotOpen        = errors.New("device is not open")
	ErrNoDeviceFound          = errors.New("no device found")
	ErrMoreThanOneDeviceFound = errors.New("more than one device found")
	ErrDeviceLocked           = errors.New("device is locked by another application")
	ErrReportIsTooBig         = errors.New("report is too big")
)

// Device is an opaque structure that represents a USB HID device connected
// to the computer.
type Device struct {
	path         string
	vendorId     uint16
	productId    uint16
	version      uint16
	manufacturer string
	product      string
	serialNumber string

	usagePage           uint16
	usage               uint16
	reportInputLength   uint16
	reportOutputLength  uint16
	reportFeatureLength uint16
	reportWithId        bool

	file  *os.File
	flock *os.File
}

// DeviceFilterFunc is a function prototype that helps defining a filter
// function to be used by the device enumeration functions.
type DeviceFilterFunc func(*Device) bool

// Enumerate lists the USB HID devices connected to the computer, optionally
// filtered by a DeviceFilterFunc function.
func Enumerate(f DeviceFilterFunc) ([]*Device, error) {
	devices, err := enumerate()
	if err != nil {
		return nil, err
	}

	if f == nil {
		return devices, nil
	}

	rv := []*Device{}
	for _, dev := range devices {
		if f(dev) {
			rv = append(rv, dev)
		}
	}
	return rv, nil
}

// Get returns a USB HID device found connected to the machine that matches the
// DeviceFilterfunc function. It can optionally open the device and acquire an
// exclusive lock.
//
// If the filtering would result in more than one device, or zero devices, an
// error is returned.
func Get(f DeviceFilterFunc, open bool, lock bool) (*Device, error) {
	devices, err := Enumerate(f)
	if err != nil {
		return nil, err
	}

	if l := len(devices); l == 0 {
		return nil, fmt.Errorf("usbhid: %w", ErrNoDeviceFound)
	} else if l > 1 {
		return nil, fmt.Errorf("usbhid: %w", ErrMoreThanOneDeviceFound)
	}

	d := devices[0]

	if open {
		if err := d.Open(lock); err != nil {
			return nil, err
		}
	}

	return devices[0], nil
}

// Open opens the USB HID device for usage.
func (d *Device) Open(lock bool) error {
	if d.file != nil {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceIsOpen)
	}

	f, err := os.OpenFile(d.path, os.O_RDWR, 0755)
	if err != nil {
		return err
	}

	d.file = f

	if lock {
		return d.lock()
	}
	return nil
}

// IsOpen checks if the USB HID device is open and available for usage
func (d *Device) IsOpen() bool {
	return d.file != nil
}

// Close closes the USB HID device
func (d *Device) Close() error {
	if d.file == nil {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceIsNotOpen)
	}

	if err := d.file.Close(); err != nil {
		return err
	}
	d.file = nil

	if d.flock != nil {
		fn := d.flock.Name()
		if err := d.flock.Close(); err != nil {
			return err
		}
		d.flock = nil
		os.Remove(fn)
	}

	return nil
}

// GetInputReport reads an input report from the USB HID device.
// It will block until a report is available, and returns the report id,
// a slice of bytes with the report content, and an error (or nil).
func (d *Device) GetInputReport() (byte, []byte, error) {
	if d.file == nil {
		return 0, nil, fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceIsNotOpen)
	}

	return d.getInputReport()
}

// SetOutputReport writes an output report to the USB HID device.
// It takes the report id and a slice of bytes with the data to be sent,
// and returns an error or nil. If the size of the slice is lower than
// the expected report size, it will be zero padded, and if it is bigger,
// an error is returned.
func (d *Device) SetOutputReport(reportId byte, data []byte) error {
	if d.file == nil {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceIsNotOpen)
	}

	if len(data) > int(d.reportOutputLength) {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrReportIsTooBig)
	}

	return d.setOutputReport(reportId, data)
}

// GetFeatureReport reads a feature report from the USB HID device.
// It may block until a report is available, depending on the operating system.
// It takes the desired report id and returns a slice of bytes with the report
// content and an error (or nil).
func (d *Device) GetFeatureReport(reportId byte) ([]byte, error) {
	if d.file == nil {
		return nil, fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceIsNotOpen)
	}

	return d.getFeatureReport(reportId)
}

// SetFeatureReport writes an output report to the USB HID device.
// It takes the report id and a slice of bytes with the data to be sent,
// and returns an error or nil. If the size of the slice is lower than
// the expected report size, it will be zero padded, and if it is bigger,
// an error is returned.
func (d *Device) SetFeatureReport(reportId byte, data []byte) error {
	if d.file == nil {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceIsNotOpen)
	}

	if len(data) > int(d.reportFeatureLength) {
		return fmt.Errorf("usbhid: %s: %w", d.path, ErrReportIsTooBig)
	}

	return d.setFeatureReport(reportId, data)
}

// GetInputReportLength returns the data size of an input report in bytes.
func (d *Device) GetInputReportLength() uint16 {
	return d.reportInputLength
}

// GetOutputReportLength returns the data size of an output report in bytes.
func (d *Device) GetOutputReportLength() uint16 {
	return d.reportOutputLength
}

// GetFeatureReportLength returns the data size of a feature report in bytes.
func (d *Device) GetFeatureReportLength() uint16 {
	return d.reportFeatureLength
}

// Path returns a string representation of the USB HID device path.
func (d *Device) Path() string {
	return d.path
}

// VendorId returns the vendor identifier of the USB HID device.
func (d *Device) VendorId() uint16 {
	return d.vendorId
}

// ProductId returns the product identifier of the USB HID device.
func (d *Device) ProductId() uint16 {
	return d.productId
}

// Version returns a BCD representation of the product version of
// the USB HID device.
func (d *Device) Version() uint16 {
	return d.version
}

// Manufacturer returns a string representation of the manufacturer of
// the USB HID device.
func (d *Device) Manufacturer() string {
	return d.manufacturer
}

// Product returns a string representation of the product name of
// the USB HID device.
func (d *Device) Product() string {
	return d.product
}

// SerialNumber returns a string representation of the serial number of
// the USB HID device.
func (d *Device) SerialNumber() string {
	return d.serialNumber
}
