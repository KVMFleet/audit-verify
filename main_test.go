//go:build !js

package main

import "testing"

func TestVacuousVerification(t *testing.T) {
	if !vacuousVerification(0) {
		t.Error("zero events must be treated as vacuous (nothing verified)")
	}
	if vacuousVerification(1) {
		t.Error("one event is a non-vacuous verification")
	}
	if vacuousVerification(663) {
		t.Error("many events is a non-vacuous verification")
	}
}

func TestBareModeIsInternalOnly(t *testing.T) {
	// No external commitment of any kind → internal-consistency-only.
	if !bareModeIsInternalOnly(false, false, false) {
		t.Error("no external check should be flagged internal-only")
	}
	// Any single external commitment lifts it out of internal-only.
	for name, args := range map[string][3]bool{
		"check-against-anchor": {true, false, false},
		"signed-anchors":       {false, true, false},
		"witness-pubkey":       {false, false, true},
		"all three":            {true, true, true},
	} {
		if bareModeIsInternalOnly(args[0], args[1], args[2]) {
			t.Errorf("%s present: must NOT be flagged internal-only", name)
		}
	}
}
