package usbhid_test

import (
	"fmt"
	"log"

	"github.com/rafaelmartins/usbhid"
)

func ExampleEnumerate() {
	devices, err := usbhid.Enumerate(nil) // no filtering
	if err != nil {
		log.Fatal(err)
	}

	for _, device := range devices {
		fmt.Printf("Device: 0x%04x:0x%04x\n", device.VendorId(), device.ProductId())
		fmt.Printf("\tManufacturer:  %s\n", device.Manufacturer())
		fmt.Printf("\tProduct:       %s\n", device.Product())
		fmt.Printf("\tSerial Number: %s\n", device.SerialNumber())
	}
}

func ExampleDeviceFilterFunc() {
	device, err := usbhid.Get(func(d *usbhid.Device) bool {
		// filtering by free HID VID/PID from v-usb
		if d.VendorId() != 0x16c0 {
			return false
		}
		if d.ProductId() != 0x05df {
			return false
		}
		return true
	}, false, false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Device: 0x%04x:0x%04x\n", device.VendorId(), device.ProductId())
	fmt.Printf("\tManufacturer:  %s\n", device.Manufacturer())
	fmt.Printf("\tProduct:       %s\n", device.Product())
	fmt.Printf("\tSerial Number: %s\n", device.SerialNumber())
}
