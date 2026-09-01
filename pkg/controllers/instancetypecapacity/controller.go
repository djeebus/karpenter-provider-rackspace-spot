/*
Copyright 2026 kanya-approve.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package instancetypecapacity

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"

	"github.com/kanya-approve/karpenter-provider-rackspace-spot/pkg/providers/instance"
	"github.com/kanya-approve/karpenter-provider-rackspace-spot/pkg/providers/instancetype"
)

// Controller feeds capacity measured from booted nodes back into the instance
// type provider, leaving the ServerClass-derived estimate in use only for a
// flavor no node has registered for yet.
type Controller struct {
	kubeClient           client.Client
	instanceTypeProvider instancetype.Provider
}

func NewController(kubeClient client.Client, instanceTypeProvider instancetype.Provider) *Controller {
	return &Controller{kubeClient: kubeClient, instanceTypeProvider: instanceTypeProvider}
}

func (c *Controller) Register(_ context.Context, mgr manager.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("instancetype.capacity").
		For(&corev1.Node{}, builder.WithPredicates(managedNode())).
		Complete(c)
}

func managedNode() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetLabels()[instance.KarpenterManagedLabel] == "true"
	})
}

func (c *Controller) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var node corev1.Node
	if err := c.kubeClient.Get(ctx, req.NamespacedName, &node); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if len(node.Status.Capacity) == 0 {
		return reconcile.Result{}, nil
	}

	nodeClaimName := node.Labels[instance.NodeClaimNameLabel]
	if nodeClaimName == "" {
		return reconcile.Result{}, nil
	}
	var nc karpv1.NodeClaim
	if err := c.kubeClient.Get(ctx, types.NamespacedName{Name: nodeClaimName}, &nc); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("getting NodeClaim %q: %w", nodeClaimName, err)
	}

	// The NodeClaim, not the Node: the OpenStack CCM overwrites the node's
	// instance-type label with the Nova flavor name (compute1-8), which has no
	// mapping back to a ServerClass.
	instanceType := nc.Labels[corev1.LabelInstanceTypeStable]
	if instanceType == "" {
		return reconcile.Result{}, nil
	}
	c.instanceTypeProvider.UpdateFromNode(instanceType, node.Status.Capacity)
	return reconcile.Result{}, nil
}
