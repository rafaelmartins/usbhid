# usbhid

[![Go Reference](https://pkg.go.dev/badge/github.com/rafaelmartins/usbhid.svg)](https://pkg.go.dev/github.com/rafaelmartins/usbhid)

A pure Go library to interact with USB HID devices. It can enumerate USB HID devices, send and receive every type of HID report.

It works on Linux, Mac and Windows.


## Known issues

Blocking API. To interact with it asynchronously please use goroutines and some synchronization primitives.

Due to most platforms not providing the full HID descriptors to applications the library can't validate report data sizes on a per-report ID basis. It can only validate the maximum report size for each report type. Library consumers should know the interfaces and provide correct data and/or validate it themselves. This is the same situation of most mainstream USB HID libraries.

On Linux several USB HID devices won't be accessible to normal users by default. Depending on the device the user may need to be added to some specific group or to create some udev rule assigning additional permissions. Solving such issues is out of scope of this library.


## License

This library is released under a BSD-3-Clause license.
