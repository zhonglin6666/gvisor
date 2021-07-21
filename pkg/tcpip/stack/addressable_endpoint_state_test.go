// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack_test

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TestAddressableEndpointStateCleanup tests that cleaning up an addressable
// endpoint state removes permanent addresses and leaves groups.
func TestAddressableEndpointStateCleanup(t *testing.T) {
	var ep fakeNetworkEndpoint
	if err := ep.Enable(); err != nil {
		t.Fatalf("ep.Enable(): %s", err)
	}

	var s stack.AddressableEndpointState
	s.Init(&ep, nil)

	addr := tcpip.AddressWithPrefix{
		Address:   "\x01",
		PrefixLen: 8,
	}

	{
		properties := stack.AddressProperties{PEB: stack.NeverPrimaryEndpoint}
		ep, err := s.AddAndAcquirePermanentAddress(addr, properties)
		if err != nil {
			t.Fatalf("s.AddAndAcquirePermanentAddress(%s, %+v): %s", addr, properties, err)
		}
		// We don't need the address endpoint.
		ep.DecRef()
	}
	{
		ep := s.AcquireAssignedAddress(addr.Address, false /* allowTemp */, stack.NeverPrimaryEndpoint)
		if ep == nil {
			t.Fatalf("got s.AcquireAssignedAddress(%s, false, NeverPrimaryEndpoint) = nil, want = non-nil", addr.Address)
		}
		ep.DecRef()
	}

	s.Cleanup()
	if ep := s.AcquireAssignedAddress(addr.Address, false /* allowTemp */, stack.NeverPrimaryEndpoint); ep != nil {
		ep.DecRef()
		t.Fatalf("got s.AcquireAssignedAddress(%s, false, NeverPrimaryEndpoint) = %s, want = nil", addr.Address, ep.AddressWithPrefix())
	}
}

func TestAddressLifetimes(t *testing.T) {
	var fakeEp fakeNetworkEndpoint
	if err := fakeEp.Enable(); err != nil {
		t.Fatalf("fakeEp.Enable(): %s", err)
	}

	var s stack.AddressableEndpointState
	clock := faketime.NewManualClock()
	s.Init(&fakeEp, stack.New(stack.Options{
		Clock: clock,
	}))

	// Add an address that is FirstPrimaryEndpoint which will be deprecated after
	// some time and then invalidated after some more time.
	addr := tcpip.AddressWithPrefix{
		Address:   "\x02",
		PrefixLen: 8,
	}
	preferredLifetime := 7 * time.Hour
	validLifetime := 12 * time.Hour

	properties := stack.AddressProperties{PEB: stack.FirstPrimaryEndpoint, PreferredLifetime: &preferredLifetime, ValidLifetime: &validLifetime}
	ep, err := s.AddAndAcquirePermanentAddress(addr, properties)
	if err != nil {
		t.Fatalf("s.AddAndAcquirePermanentAddress(%s, %+v): %s", addr, properties, err)
	}

	got := s.AcquireOutgoingPrimaryAddress("", false /* allowExpired */)
	if got != ep {
		t.Fatalf("got s.AcquireOutgoingPrimaryAddress(\"\", false) = nil, want = %+v", ep)
	}
	got.DecRef()

	clock.Advance(preferredLifetime + time.Hour)

	if !ep.Deprecated() {
		t.Fatalf("got ep.Deprecated() = false, want = true")
	}
	{
		addr := tcpip.AddressWithPrefix{
			Address:   "\x03",
			PrefixLen: 8,
		}
		ep, err := s.AddAndAcquirePermanentAddress(addr, stack.AddressProperties{})
		if err != nil {
			t.Fatalf("s.AddAndAcquirePermanentAddress(%s, {}): %s", addr, err)
		}

		got := s.AcquireOutgoingPrimaryAddress("", false /* allowExpired */)
		if got != ep {
			t.Fatalf("got s.AcquireOutgoingPrimaryAddress(\"\", false) = nil, want = %+v", ep)
		}
		got.DecRef()

		ep.DecRef()
		if err := s.RemovePermanentEndpoint(ep); err != nil {
			t.Fatalf("s.RemovePermanentEndpoint(ep): %s", err)
		}
	}

	clock.Advance(validLifetime - preferredLifetime)
	if got := s.AcquireOutgoingPrimaryAddress("", false /* allowExpired */); got != nil {
		t.Fatalf("got s.AcquireOutgoingPrimaryAddress(\"\", false) = %+v, want = nil", got)
	}
	got.DecRef()
}
