/*
Copyright 2026 kanya-approve.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package main

import (
	"fmt"
	"os"
	"time"

	opcontroller "github.com/awslabs/operatorpkg/controller"
	karpcloudprovider "sigs.k8s.io/karpenter/pkg/cloudprovider"
	"sigs.k8s.io/karpenter/pkg/cloudprovider/overlay"
	"sigs.k8s.io/karpenter/pkg/controllers"
	nodeclaimlifecycle "sigs.k8s.io/karpenter/pkg/controllers/nodeclaim/lifecycle"
	"sigs.k8s.io/karpenter/pkg/controllers/state"
	karpoperator "sigs.k8s.io/karpenter/pkg/operator"

	rscloudprovider "github.com/kanya-approve/karpenter-provider-rackspace-spot/pkg/cloudprovider"
	"github.com/kanya-approve/karpenter-provider-rackspace-spot/pkg/controllers/instancetypecapacity"
	"github.com/kanya-approve/karpenter-provider-rackspace-spot/pkg/controllers/nodeclass"
	"github.com/kanya-approve/karpenter-provider-rackspace-spot/pkg/controllers/nodelink"
	rsoperator "github.com/kanya-approve/karpenter-provider-rackspace-spot/pkg/operator"
)

// Rackspace took 17m from winning a bid to a joined node when timed end to end,
// and longer in other attempts. LaunchTimeout is the only budget upstream
// exposes as a variable; see CloudProvider.Create for why the wait lands here.
const defaultLaunchTimeout = 30 * time.Minute

func main() {
	if v := os.Getenv("RACKSPACE_LAUNCH_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			panic(fmt.Errorf("parsing RACKSPACE_LAUNCH_TIMEOUT %q: %w", v, err))
		}
		nodeclaimlifecycle.LaunchTimeout = d
	} else {
		nodeclaimlifecycle.LaunchTimeout = defaultLaunchTimeout
	}

	ctx, coreOp := karpoperator.NewOperator()
	ctx, op := rsoperator.NewOperator(ctx, coreOp)

	var raw karpcloudprovider.CloudProvider = rscloudprovider.New(op)
	cp := overlay.Decorate(raw, op.GetClient(), op.InstanceTypeStore)
	clusterState := state.NewCluster(op.Clock, op.GetClient(), cp)

	providerControllers := []opcontroller.Controller{
		nodeclass.NewController(op.GetClient(), op.InstanceTypeProvider, op.Region),
		nodelink.NewController(op.GetClient()),
		instancetypecapacity.NewController(op.GetClient(), op.InstanceTypeProvider),
	}

	op.
		WithControllers(ctx, append(
			controllers.NewControllers(
				ctx,
				op.Manager,
				op.Clock,
				op.GetClient(),
				op.EventRecorder,
				cp,
				raw,
				clusterState,
				op.InstanceTypeStore,
			),
			providerControllers...,
		)...).
		Start(ctx)
}
