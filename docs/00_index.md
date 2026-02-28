---
menu: Main
---
**A pure Go library for interacting with USB HID devices, supporting Linux, macOS, and Windows.**

## Overview

usbhid is a Go library that provides userspace access to USB HID (Human Interface Device) devices. It handles device enumeration, opening, and bidirectional communication through all HID report types: input, output, and feature reports.

The library is written in pure Go with no cgo dependency. On Linux, it accesses devices through the hidraw subsystem via sysfs and ioctl. On macOS, it calls IOKit and CoreFoundation through [purego](https://github.com/ebitengine/purego). On Windows, it uses the SetupAPI and HID APIs via syscall.

## Key highlights

- **Pure Go** -- no cgo required on any platform
- **Cross-platform** -- supports Linux, macOS, and Windows with platform-native backends
- **All HID report types** -- read/write input, output, and feature reports
- **Device filtering** -- enumerate and select devices by vendor ID, product ID, usage page, or any device property
- **Exclusive locking** -- optional per-device locking to prevent concurrent access from other applications
- **BSD 3-Clause license** -- permissive open-source licensing

## Usage

Enumerate all connected USB HID devices:

```go
devices, err := usbhid.Enumerate(nil)
if err != nil {
    log.Fatal(err)
}

for _, device := range devices {
    fmt.Printf("Device: 0x%04x:0x%04x\n", device.VendorId(), device.ProductId())
    fmt.Printf("\tManufacturer:  %s\n", device.Manufacturer())
    fmt.Printf("\tProduct:       %s\n", device.Product())
    fmt.Printf("\tSerial Number: %s\n", device.SerialNumber())
    fmt.Printf("\tUsage:         0x%04x/0x%04x\n", device.UsagePage(), device.Usage())
}
```

Find and open a specific device using a filter function:

```go
device, err := usbhid.Get(func(d *usbhid.Device) bool {
    return d.VendorId() == 0x16c0 && d.ProductId() == 0x05df
}, true, true)
if err != nil {
    log.Fatal(err)
}
defer device.Close()
```

## Requirements

- Go 1.19 or later

## Explore further

- [Development guide](10_development-guide.md) -- integration, API overview, and platform details
- [API documentation](https://pkg.go.dev/rafaelmartins.com/p/usbhid) -- complete API reference on pkg.go.dev
- [Source code](https://github.com/rafaelmartins/usbhid) -- GitHub repository
