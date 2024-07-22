// Copyright 2022-2024 Rafael G. Martins. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package usbhid

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

type deviceExtra struct {
	file *os.File
}

func sysfsReadAsBytes(dir string, entry string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, entry))
}

func sysfsReadAsString(dir string, entry string) (string, error) {
	b, err := sysfsReadAsBytes(dir, entry)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func sysfsReadAsUint(dir string, entry string, base int, bitSize int) (uint64, error) {
	v, err := sysfsReadAsString(dir, entry)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(v, base, bitSize)
}

func sysfsReadAsHexUint16(dir string, entry string) (uint16, error) {
	v, err := sysfsReadAsUint(dir, entry, 16, 16)
	return uint16(v), err
}

func enumerate() ([]*Device, error) {
	rv := []*Device{}

	if err := filepath.Walk("/sys/bus/usb/devices", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.Mode()&os.ModeSymlink == 0 || strings.Contains(info.Name(), ":") {
			return nil
		}

		d := &Device{}

		d.vendorId, err = sysfsReadAsHexUint16(path, "idVendor")
		if err != nil {
			return nil
		}

		d.productId, err = sysfsReadAsHexUint16(path, "idProduct")
		if err != nil {
			return nil
		}

		d.version, err = sysfsReadAsHexUint16(path, "bcdDevice")
		if err != nil {
			return nil
		}

		if m, err := sysfsReadAsString(path, "manufacturer"); err == nil {
			d.manufacturer = m
		}

		if p, err := sysfsReadAsString(path, "product"); err == nil {
			d.product = p
		}

		if s, err := sysfsReadAsString(path, "serial"); err == nil {
			d.serialNumber = s
		}

		f, err := filepath.Glob(filepath.Join(path, "*", "*", "hidraw", "hidraw[0-9]*"))
		if err != nil {
			return nil
		}
		if len(f) != 1 {
			return nil
		}

		hidpath := filepath.Dir(filepath.Dir(f[0]))
		descriptor, err := sysfsReadAsBytes(hidpath, "report_descriptor")
		if err != nil {
			return nil
		}

		d.path = filepath.Join("/dev", filepath.Base(f[0]))
		d.usagePage, d.usage, d.reportInputLength, d.reportOutputLength, d.reportFeatureLength, d.reportWithId = hidParseReportDescriptor(descriptor)

		rv = append(rv, d)

		return nil
	}); err != nil {
		return nil, err
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
		if err := syscall.Flock(int(d.extra.file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == syscall.EWOULDBLOCK {
			return fmt.Errorf("usbhid: %s: %w", d.path, ErrDeviceLocked)
		}
	}
	return nil
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

	return nil
}

func (d *Device) getInputReport() (byte, []byte, error) {
	buflen := d.reportInputLength
	if d.reportWithId {
		buflen++
	}

	buf := make([]byte, buflen)

	n, err := d.extra.file.Read(buf)
	if err != nil {
		return 0, nil, err
	}

	if d.reportWithId {
		return buf[0], buf[1:n], nil
	}
	return 0, buf[:n], nil
}

func (d *Device) setOutputReport(reportId byte, data []byte) error {
	buf := append([]byte{reportId}, data...)
	_, err := d.extra.file.Write(buf)
	return err
}

func (d *Device) getFeatureReport(reportId byte) ([]byte, error) {
	buf := make([]byte, d.reportFeatureLength+1)
	if d.reportWithId {
		buf[0] = reportId
	}

	rv, err := ioctl(d.extra.file.Fd(), uint(ioc(iocWrite|iocRead, 'H', 0x07, uint16(len(buf)))), uintptr(unsafe.Pointer(&buf[0])))
	if err != nil {
		return nil, err
	}

	start := 0
	if d.reportWithId {
		start++
		rv--
	}
	return buf[start : start+rv], nil
}

func (d *Device) setFeatureReport(reportId byte, data []byte) error {
	buf := append([]byte{reportId}, data...)
	_, err := ioctl(d.extra.file.Fd(), uint(ioc(iocWrite|iocRead, 'H', 0x06, uint16(len(buf)))), uintptr(unsafe.Pointer(&buf[0])))
	return err
}
