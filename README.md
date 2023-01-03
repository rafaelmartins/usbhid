# usbhid

[![Go Reference](https://pkg.go.dev/badge/github.com/rafaelmartins/usbhid.svg)](https://pkg.go.dev/github.com/rafaelmartins/usbhid)

A pure Go library to interact with USB HID devices.

It works on Linux and Windows.

## Known issues

macOS is not supported. I don't own any hardware capable of running it.

On Linux, several USB HID devices won't be accessible by normal users. Depending on the device, the user may need to be added to some specific group or to create some udev rule giving additional permissions. Solving such issues is out of scope of this library.

## License

This library is released under a BSD-3-Clause license.
