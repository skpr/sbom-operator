// Package skprrelease creates an SBOM object for each image in a Skpr Release.
package skprrelease

import (
	"context"
	"fmt"
	"hash/fnv"
	"strconv"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1beta1 "github.com/skpr/sbom-operator/apis/security/v1beta1"
	skprv1beta1 "github.com/skpr/sbom-operator/internal/skpr/v1beta1"
)

// ControllerName used for identifying which controller is performing an operation.
const ControllerName = "skpr-release"

// Reconciler creates an SBOM object for each image in a Release.
type Reconciler struct {
	client.Client
}

// +kubebuilder:rbac:groups=workflow.skpr.io,resources=releases,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.skpr.io,resources=sboms,verbs=create

// Reconcile creates an SBOM object for each image in a Release.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	release := &skprv1beta1.Release{}

	if err := r.Get(ctx, req.NamespacedName, release); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Releases which are being deleted will have their SBOMs garbage collected.
	if !release.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	for key, image := range release.Spec.Images {
		sbom := &securityv1beta1.SBOM{
			ObjectMeta: metav1.ObjectMeta{
				Name:      Name(release.Name, key),
				Namespace: release.Namespace,
			},
			Spec: securityv1beta1.SBOMSpec{
				Image: image.URI,
			},
		}

		if err := controllerutil.SetControllerReference(release, sbom, r.Scheme()); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to set controller reference: %w", err)
		}

		// Releases are immutable so we only need to create the SBOM once.
		err := r.Create(ctx, sbom)
		if kerrors.IsAlreadyExists(err) {
			continue
		}

		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create SBOM for image %s: %w", key, err)
		}

		logger.Info("Created SBOM", "sbom", sbom.Name, "image", image.URI)
	}

	return ctrl.Result{}, nil
}

// Name of the SBOM object for an image within a Release.
func Name(release, image string) string {
	name := fmt.Sprintf("%s-%s", release, image)

	if len(validation.IsDNS1123Subdomain(name)) == 0 {
		return name
	}

	// Fallback to a hash if the image key cannot be used in an object name.
	h := fnv.New64a()
	h.Write([]byte(image))

	return fmt.Sprintf("%s-%s", release, strconv.FormatUint(h.Sum64(), 36))
}

// SetupWithManager declares when the reconciler should be triggered.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(ControllerName).
		For(&skprv1beta1.Release{}).
		Owns(&securityv1beta1.SBOM{}).
		Complete(r)
}
