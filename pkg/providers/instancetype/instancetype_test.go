/*
Copyright 2026 kanya-approve.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package instancetype

import (
	"testing"

	rxtspot "github.com/rackspace-spot/spot-go-sdk/api/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
)

func TestTranslate_CPUOnly(t *testing.T) {
	sc := rxtspot.ServerClass{
		Name:                      "gp.vs1.small-dfw",
		Region:                    "us-central-dfw-1",
		Availability:              "available",
		OnDemandPricePerHour:      "0.10",
		CurrentMarketPricePerHour: "0.04",
		Resources:                 rxtspot.Resource{CPU: "2", Memory: "8Gi"},
	}
	it := translate(sc, "100GB", nil)

	if it.Name != sc.Name {
		t.Errorf("Name = %q, want %q", it.Name, sc.Name)
	}
	if got := it.Capacity[corev1.ResourceCPU]; got.String() != "2" {
		t.Errorf("CPU capacity = %q, want 2", got.String())
	}
	if got, want := it.Capacity[corev1.ResourceMemory], shave(resource.MustParse("8Gi"), defaultVMMemoryOverheadPercent); got.Cmp(want) != 0 {
		t.Errorf("Memory capacity = %q, want %q (8Gi less VM overhead)", got.String(), want.String())
	}
	if got, want := it.Capacity[corev1.ResourceEphemeralStorage], shave(resource.MustParse("100Gi"), defaultVMDiskOverheadPercent); got.Cmp(want) != 0 {
		t.Errorf("ephemeral-storage capacity = %q, want %q (100Gi disk less VM overhead)", got.String(), want.String())
	}
	if _, hasGPU := it.Capacity[resourceNvidiaGPU]; hasGPU {
		t.Errorf("expected no GPU capacity for CPU-only ServerClass")
	}
	if pods := it.Capacity[corev1.ResourcePods]; pods.Value() != defaultPodsPerNode {
		t.Errorf("Pods capacity = %d, want %d", pods.Value(), defaultPodsPerNode)
	}
	if len(it.Offerings) != 2 {
		t.Fatalf("expected 2 offerings (spot + on-demand), got %d", len(it.Offerings))
	}
}

func TestTranslate_GPUOnly(t *testing.T) {
	sc := rxtspot.ServerClass{
		Name:                      "gpu.h100-sjc",
		Region:                    "us-west-sjc-1",
		Availability:              "available",
		OnDemandPricePerHour:      "3.50",
		CurrentMarketPricePerHour: "1.10",
		Resources:                 rxtspot.Resource{CPU: "16", Memory: "128Gi", GPU: "1"},
	}
	it := translate(sc, "", nil)
	if got, ok := it.Capacity[resourceNvidiaGPU]; !ok || got.Value() != 1 {
		t.Errorf("nvidia.com/gpu = %v (ok=%v), want 1", got, ok)
	}
	if got, want := it.Capacity[corev1.ResourceEphemeralStorage], shave(resource.MustParse("40Gi"), defaultVMDiskOverheadPercent); got.Cmp(want) != 0 {
		t.Errorf("ephemeral-storage fallback = %q, want %q (40Gi less VM overhead)", got.String(), want.String())
	}
}

func TestTranslate_UnavailableMarksOfferings(t *testing.T) {
	sc := rxtspot.ServerClass{
		Name:                      "gp.vs1.tiny",
		Region:                    "us-central-dfw-1",
		Availability:              "unavailable",
		OnDemandPricePerHour:      "0.02",
		CurrentMarketPricePerHour: "0.01",
		Resources:                 rxtspot.Resource{CPU: "1", Memory: "2Gi"},
	}
	it := translate(sc, "", nil)
	for _, of := range it.Offerings {
		if of.Available {
			t.Errorf("expected unavailable offerings, got Available=true on %v", of.Requirements)
		}
	}
}

func TestTranslate_ZeroPriceDropsOffering(t *testing.T) {
	sc := rxtspot.ServerClass{
		Name:                 "gp.vs1.no-spot",
		Region:               "us-central-dfw-1",
		Availability:         "available",
		OnDemandPricePerHour: "0.05",
		// No CurrentMarketPricePerHour: spot offering should be omitted.
		Resources: rxtspot.Resource{CPU: "1", Memory: "2Gi"},
	}
	it := translate(sc, "", nil)
	if len(it.Offerings) != 1 {
		t.Fatalf("expected only on-demand offering, got %d", len(it.Offerings))
	}
	if !it.Offerings[0].Requirements.Has(karpv1.CapacityTypeLabelKey) {
		t.Fatal("offering missing capacity-type requirement")
	}
	got := it.Offerings[0].Requirements.Get(karpv1.CapacityTypeLabelKey).Any()
	if got != karpv1.CapacityTypeOnDemand {
		t.Errorf("expected on-demand offering, got %q", got)
	}
}

func TestParsePrice_StripsDollarPrefix(t *testing.T) {
	cases := map[string]float64{
		"$0.001000": 0.001,
		"$0.035":    0.035,
		"  $1.234 ": 1.234,
		"":          0,
		"$":         0,
		"garbage":   0,
		"0.5":       0.5,
	}
	for in, want := range cases {
		if got := parsePrice(in); got != want {
			t.Errorf("parsePrice(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseQuantity_HandlesRackspaceUnits(t *testing.T) {
	cases := map[string]string{
		"3.75GB": "3.75Gi",
		"60GB":   "60Gi",
		"500MB":  "500Mi",
		"2":      "2",
	}
	for in, want := range cases {
		got := parseQuantity(in)
		wantQ := resource.MustParse(want)
		if got.Cmp(wantQ) != 0 {
			t.Errorf("parseQuantity(%q) = %v, want %v", in, got.String(), want)
		}
	}
}

// real* are measured from registered nodes in a live Cloudspace:
// kubectl get node -o jsonpath='{.status.allocatable}'
func TestTranslate_AllocatableFitsRealNodes(t *testing.T) {
	cases := []struct {
		name                               string
		cpu, memory, disk                  string
		realCPU, realMemory, realEphemeral string
	}{
		{"ch.vs1.large-iad", "4", "7580Mi", "100GB", "3500m", "6457304Ki", "91331288934"},
		{"ch.vs1.xlarge-iad", "8", "15Gi", "100GB", "7500m", "14186448Ki", "91331288934"},
		{"mh.vs1.medium-iad", "2", "15Gi", "100GB", "1500m", "14186460Ki", "91331288934"},
		{"gp.vs1.medium-iad", "2", "3740Mi", "100GB", "1500m", "2659036Ki", "91331288934"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			it := translate(rxtspot.ServerClass{
				Name:                      tc.name,
				Region:                    "us-east-iad-1",
				Availability:              "available",
				CurrentMarketPricePerHour: "0.05",
				Resources:                 rxtspot.Resource{CPU: tc.cpu, Memory: tc.memory},
			}, tc.disk, nil)

			allocatable := it.Allocatable()
			for res, real := range map[corev1.ResourceName]string{
				corev1.ResourceCPU:              tc.realCPU,
				corev1.ResourceMemory:           tc.realMemory,
				corev1.ResourceEphemeralStorage: tc.realEphemeral,
			} {
				got, want := allocatable[res], resource.MustParse(real)
				if got.Cmp(want) > 0 {
					t.Errorf("%s allocatable = %s, exceeds what the node reports (%s)", res, got.String(), want.String())
				}
			}
		})
	}
}

func TestUpdateFromNode_KeepsSmallestObserved(t *testing.T) {
	p := NewProvider(nil)
	const it = "ch.vs1.large-iad"

	p.UpdateFromNode(it, corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("7608280Ki")})
	p.UpdateFromNode(it, corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("7600000Ki")})
	p.UpdateFromNode(it, corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("7700000Ki")})

	got := p.discoveredFor(it)[corev1.ResourceMemory]
	if want := resource.MustParse("7600000Ki"); got.Cmp(want) != 0 {
		t.Errorf("memory = %q, want %q", got.String(), want.String())
	}
	if _, ok := p.discoveredFor(it)[corev1.ResourceCPU]; ok {
		t.Errorf("cpu should not be discovered, it is advertised exactly")
	}
}

func TestUpdateFromNode_IgnoresUnreportedResources(t *testing.T) {
	p := NewProvider(nil)
	const it = "gp.vs1.medium-iad"

	p.UpdateFromNode(it, corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("3810012Ki")})
	p.UpdateFromNode(it, corev1.ResourceList{})

	got := p.discoveredFor(it)[corev1.ResourceMemory]
	if want := resource.MustParse("3810012Ki"); got.Cmp(want) != 0 {
		t.Errorf("memory = %q, want %q — an empty report should not clear the measurement", got.String(), want.String())
	}
}

func TestTranslate_DiscoveredCapacityReplacesEstimate(t *testing.T) {
	sc := rxtspot.ServerClass{
		Name:                      "ch.vs1.large-iad",
		Region:                    "us-east-iad-1",
		Availability:              "available",
		CurrentMarketPricePerHour: "0.05",
		Resources:                 rxtspot.Resource{CPU: "4", Memory: "7580Mi"},
	}
	measured := resource.MustParse("7608280Ki")
	it := translate(sc, "100GB", corev1.ResourceList{corev1.ResourceMemory: measured})

	if got := it.Capacity[corev1.ResourceMemory]; got.Cmp(measured) != 0 {
		t.Errorf("Memory capacity = %q, want the measured %q", got.String(), measured.String())
	}
	// Byte-for-byte what that node reports as allocatable.
	if got, want := it.Allocatable()[corev1.ResourceMemory], resource.MustParse("6457304Ki"); got.Cmp(want) != 0 {
		t.Errorf("Memory allocatable = %q, want %q", got.String(), want.String())
	}
}
