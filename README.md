# usbhid

[![Go Reference](https://pkg.go.dev/badge/rafaelmartins.com/p/usbhid.svg)](https://pkg.go.dev/rafaelmartins.com/p/usbhid)

A pure Go library for interacting with USB HID devices. It can enumerate devices, send and receive all types of HID reports.

It is compatible with Linux, macOS, and Windows.


## Known issues

Blocking API. To interact with it asynchronously, use goroutines, channels, or synchronization primitives.

Due to Windows not allowing user-space applications to access the full HID report descriptors, this library can't validate report data sizes on a per-report basis. Instead, it can only confirm the largest possible report size for each report category. Library consumers should know the report descriptors and ensure that their data adheres to them, or implement their own validation checks. The same is true for most mainstream USB HID libraries.

Linux: Several USB HID devices are inaccessible to regular users by default. Depending on the device, the user may need to be added to a specific group or create a udev rule to grant additional permissions. Addressing these matters falls outside the scope of this library.


## License

This library is distributed under a BSD 3-Clause license.
