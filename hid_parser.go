// Copyright 2022-2023 Rafael G.Martins. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package usbhid

import (
	"math"
)

func hidValue(size byte, buf []byte) uint32 {
	switch size {
	case 0:
		return 0
	case 1:
		return uint32(buf[0])
	case 2:
		return uint32(buf[1])<<8 | uint32(buf[0])
	case 4:
		return uint32(buf[3])<<24 | uint32(buf[2])<<16 | uint32(buf[1])<<8 | uint32(buf[0])
	}
	return 0
}

func hidParseReportDescriptor(descriptor []byte) (uint16, uint16, uint16, uint16, uint16, bool) {
	var (
		withId       bool
		rcollectionl byte
		rcount       uint32
		rsize        uint32
		rusagePage   uint16
		rusage       uint16
		sinput       uint16
		soutput      uint16
		sfeature     uint16
	)

	for i := 0; i < len(descriptor); {
		var (
			tag  = (descriptor[i] & 0b11110000) >> 4
			typ  = (descriptor[i] & 0b1100) >> 2
			size = descriptor[i] & 0b11
		)

		i++

		if size == 3 {
			size = 4
		}

		switch typ {
		case 0: // main
			switch tag {
			case 8: // input
				if s := uint16(math.Ceil(float64(rcount*rsize) / 8)); s > sinput {
					sinput = s
				}

			case 9: // output
				if s := uint16(math.Ceil(float64(rcount*rsize) / 8)); s > soutput {
					soutput = s
				}

			case 10: // collection
				rcollectionl++

			case 11: // feature
				if s := uint16(math.Ceil(float64(rcount*rsize) / 8)); s > sfeature {
					sfeature = s
				}

			case 12: // collection end
				rcollectionl--
			}

		case 1: // global
			switch tag {
			case 0: // usage page
				if rcollectionl == 0 {
					rusagePage = uint16(hidValue(size, descriptor[i:]))
				}

			case 7: // report size
				rsize = hidValue(size, descriptor[i:])

			case 8: // report id}
				withId = true

			case 9: // report count
				rcount = hidValue(size, descriptor[i:])
			}

		case 2: // local
			switch tag {
			case 0: // usage
				if rcollectionl == 0 {
					rusage = uint16(hidValue(size, descriptor[i:]))
				}
			}
		}

		i += int(size)
	}

	return rusagePage, rusage, sinput, soutput, sfeature, withId
}
