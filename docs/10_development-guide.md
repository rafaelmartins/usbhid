# Development guide

usbhid provides device enumeration, filtering, and bidirectional HID report communication from pure Go. This guide covers integration, the API surface, platform-specific behavior, and known limitations.

For complete function signatures and type definitions, see the [API documentation](https://pkg.go.dev/rafaelmartins.com/p/usbhid).

## Integration

### Installation

```bash
go get rafaelmartins.com/p/usbhid
```

The module requires Go 1.19 or later. The only external dependency is [purego](https://github.com/ebitengine/purego), used on macOS to call IOKit and CoreFoundation without cgo.

### Import

```go
import "rafaelmartins.com/p/usbhid"
```

## API overview

### Device enumeration

[`Enumerate`](https://pkg.go.dev/rafaelmartins.com/p/usbhid#Enumerate) lists all USB HID devices connected to the computer. It accepts an optional [`DeviceFilterFunc`](https://pkg.go.dev/rafaelmartins.com/p/usbhid#DeviceFilterFunc) to narrow results. Pass `nil` to return all devices.

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

### Filtering and getting a single device

[`DeviceFilterFunc`](https://pkg.go.dev/rafaelmartins.com/p/usbhid#DeviceFilterFunc) is a function type (`func(*Device) bool`) used to select devices by their properties. It can be passed to both `Enumerate` and `Get`.

[`Get`](https://pkg.go.dev/rafaelmartins.com/p/usbhid#Get) returns exactly one device matching the filter. It returns an error if zero or more than one device matches. It can optionally open the device and acquire an exclusive lock in the same call.

```go
device, err := usbhid.Get(func(d *usbhid.Device) bool {
    return d.VendorId() == 0x16c0 && d.ProductId() == 0x05df
}, true, true)
if err != nil {
    log.Fatal(err)
}
defer device.Close()
```

The second argument (`open`) controls whether the device is opened immediately. The third argument (`lock`) requests an exclusive lock, preventing other applications from accessing the device concurrently.

### Device properties

The [`Device`](https://pkg.go.dev/rafaelmartins.com/p/usbhid#Device) struct is opaque. Its properties are accessed through getter methods:

| Method | Return type | Description |
|--------|-------------|-------------|
| `Path()` | `string` | Platform-specific device path |
| `VendorId()` | `uint16` | USB vendor ID |
| `ProductId()` | `uint16` | USB product ID |
| `Version()` | `uint16` | BCD-encoded product version |
| `Manufacturer()` | `string` | Manufacturer string descriptor |
| `Product()` | `string` | Product string descriptor |
| `SerialNumber()` | `string` | Serial number string descriptor |
| `UsagePage()` | `uint16` | HID usage page |
| `Usage()` | `uint16` | HID usage ID |
| `GetInputReportLength()` | `uint16` | Input report data size in bytes |
| `GetOutputReportLength()` | `uint16` | Output report data size in bytes |
| `GetFeatureReportLength()` | `uint16` | Feature report data size in bytes |

The `String()` method returns a human-readable representation including vendor ID, product ID, and available string descriptors.

### Opening and closing

[`Open`](https://pkg.go.dev/rafaelmartins.com/p/usbhid#Device.Open) opens the device for I/O. Pass `true` to request an exclusive lock. [`Close`](https://pkg.go.dev/rafaelmartins.com/p/usbhid#Device.Close) releases the device and any held lock. [`IsOpen`](https://pkg.go.dev/rafaelmartins.com/p/usbhid#Device.IsOpen) reports whether the device is currently open.

```go
if err := device.Open(true); err != nil {
    log.Fatal(err)
}
defer device.Close()
```

Calling `Open` on an already-open device returns `ErrDeviceIsOpen`. Calling `Close` on a closed device returns `ErrDeviceIsClosed`. If another application holds the lock, `Open` returns `ErrDeviceLocked`.

### Reading input reports

[`GetInputReport`](https://pkg.go.dev/rafaelmartins.com/p/usbhid#Device.GetInputReport) blocks until an input report is available, then returns the report ID and the report data as a byte slice.

```go
reportId, data, err := device.GetInputReport()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Report ID: %d, Data: %x\n", reportId, data)
```

> [!NOTE]
> This call blocks the calling goroutine. To read reports without blocking other work, call it from a dedicated goroutine and communicate results through channels.

### Writing output reports

[`SetOutputReport`](https://pkg.go.dev/rafaelmartins.com/p/usbhid#Device.SetOutputReport) sends an output report. Provide the report ID and the data to send. If the data is longer than the expected report size, `ErrReportBufferOverflow` is returned.

```go
err := device.SetOutputReport(0x01, []byte{0x00, 0x01, 0x02})
if err != nil {
    log.Fatal(err)
}
```

### Feature reports

[`GetFeatureReport`](https://pkg.go.dev/rafaelmartins.com/p/usbhid#Device.GetFeatureReport) reads a feature report by ID. [`SetFeatureReport`](https://pkg.go.dev/rafaelmartins.com/p/usbhid#Device.SetFeatureReport) writes a feature report. The same overflow rules apply to `SetFeatureReport` as to `SetOutputReport`.

```go
data, err := device.GetFeatureReport(0x01)
if err != nil {
    log.Fatal(err)
}

err = device.SetFeatureReport(0x01, []byte{0x00, 0x01})
if err != nil {
    log.Fatal(err)
}
```

### Error handling

All errors returned by the library can be tested against sentinel error values using `errors.Is`:

| Error | Condition |
|-------|-----------|
| `ErrDeviceEnumerationFailed` | Device enumeration failed at the OS level |
| `ErrDeviceFailedToOpen` | Device could not be opened |
| `ErrDeviceFailedToClose` | Device could not be closed |
| `ErrDeviceIsOpen` | `Open` called on an already-open device |
| `ErrDeviceIsClosed` | I/O or `Close` called on a closed device |
| `ErrDeviceLocked` | Device is locked by another application |
| `ErrNoDeviceFound` | `Get` found zero matching devices |
| `ErrMoreThanOneDeviceFound` | `Get` found more than one matching device |
| `ErrReportBufferOverflow` | Report data exceeds the expected size |
| `ErrGetInputReportFailed` | Input report read failed |
| `ErrGetFeatureReportFailed` | Feature report read failed |
| `ErrSetOutputReportFailed` | Output report write failed |
| `ErrSetFeatureReportFailed` | Feature report write failed |

Errors wrap the sentinel values, so `errors.Is(err, usbhid.ErrDeviceLocked)` works even when the error includes additional context.

## Platform details

### Linux

The Linux backend enumerates devices by walking `/sys/bus/usb/devices` and reading sysfs attributes (`idVendor`, `idProduct`, `bcdDevice`, `manufacturer`, `product`, `serial`). HID report descriptors are read from sysfs and parsed to extract usage page, usage, and report sizes. Devices are accessed through `/dev/hidrawN` nodes using standard file I/O and ioctl.

Exclusive locking uses `flock(2)` with `LOCK_EX|LOCK_NB`.

The ioctl encoding is architecture-aware and supports: `386`, `amd64`, `arm`, `arm64`, `loong64`, `riscv64`, `s390x`, `mips`, `mips64`, `mips64le`, `mipsle`, `ppc`, `ppc64`, `ppc64le`, and `sparc64`.

> [!NOTE]
> Many USB HID devices are inaccessible to regular users by default on Linux. Depending on the device, the user may need to be added to a specific group (e.g. `plugdev` or `input`) or create a udev rule to grant access. This is outside the scope of this library.

### macOS

The macOS backend uses IOKit's HID Manager through [purego](https://github.com/ebitengine/purego) to call CoreFoundation and IOKit functions without cgo. Device properties are read from the IOKit registry. HID report descriptors are obtained from the `ReportDescriptor` property and parsed by the library.

A dedicated goroutine runs a CFRunLoop to receive input report and device removal callbacks. The library handles device disconnection gracefully -- a blocking `GetInputReport` call returns `ErrDeviceIsClosed` if the device is unplugged while waiting.

Exclusive locking uses `kIOHIDOptionsTypeSeizeDevice`.

### Windows

The Windows backend uses SetupAPI for device enumeration and `hid.dll` for HID-specific operations. Device attributes and capabilities are obtained through `HidD_GetAttributes` and `HidP_GetCaps`. I/O uses overlapped operations through the kernel32 API.

Exclusive locking is implemented through a lock file in the system's temporary directory (derived from a SHA-1 hash of the device path) using `LockFile`.

> [!WARNING]
> Windows does not allow user-space applications to access full HID report descriptors. As a result, the library cannot validate report data sizes on a per-report basis -- it can only verify the largest possible size for each report category (input, output, feature). Library consumers should know the report descriptors for their target devices and ensure data adheres to them, or implement their own validation.

## Source files

| File | Purpose |
|------|---------|
| `device.go` | Platform-independent API: `Device` struct, `Enumerate`, `Get`, report methods, error definitions |
| `device_linux.go` | Linux backend: sysfs enumeration, hidraw I/O, ioctl |
| `device_darwin.go` | macOS backend: IOKit HID Manager, CoreFoundation bindings via purego, CFRunLoop-based input |
| `device_windows.go` | Windows backend: SetupAPI enumeration, HID.dll operations, overlapped I/O |
| `hid_parser.go` | HID report descriptor parser: extracts usage page, usage, and report sizes |
| `hid_parser_test.go` | Tests for the HID report descriptor parser |
| `example_test.go` | Runnable examples for `Enumerate` and `DeviceFilterFunc` |

## Known limitations

- **Blocking API.** All I/O operations block the calling goroutine. To interact with devices asynchronously, use goroutines, channels, or synchronization primitives. Ongoing I/O operations are not cancelled when the device is closed.
- **Windows report size validation.** Due to Windows API limitations, the library cannot validate report data sizes per individual report ID -- only the largest size per report category is known. This is a platform constraint shared by most mainstream USB HID libraries.
- **Linux device permissions.** Some HID devices require additional permissions. The library does not manage udev rules or group membership.
