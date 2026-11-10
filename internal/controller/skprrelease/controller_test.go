package skprrelease

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1beta1 "github.com/skpr/sbom-operator/apis/security/v1beta1"
	skprv1beta1 "github.com/skpr/sbom-operator/internal/skpr/v1beta1"
)

func TestReconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, securityv1beta1.AddToScheme(scheme))
	assert.NoError(t, skprv1beta1.AddToScheme(scheme))

	release := &skprv1beta1.Release{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "0.0.1",
			Namespace: "project-a",
		},
		Spec: skprv1beta1.ReleaseSpec{
			Images: map[string]skprv1beta1.ReleaseSpecImage{
				"app": {
					URI: "example.com/app:0.0.1-app",
				},
				"nginx": {
					URI: "example.com/app:0.0.1-nginx",
				},
			},
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(release).Build()

	reconciler := Reconciler{
		Client: client,
	}

	request := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      release.Name,
			Namespace: release.Namespace,
		},
	}

	_, err := reconciler.Reconcile(context.TODO(), request)
	assert.NoError(t, err)

	// Reconciling again should not fail now that the SBOMs exist.
	_, err = reconciler.Reconcile(context.TODO(), request)
	assert.NoError(t, err)

	for key, image := range release.Spec.Images {
		sbom := &securityv1beta1.SBOM{}

		err = client.Get(context.TODO(), types.NamespacedName{
			Name:      Name(release.Name, key),
			Namespace: release.Namespace,
		}, sbom)
		assert.NoError(t, err)

		assert.Equal(t, image.URI, sbom.Spec.Image)
		assert.Len(t, sbom.OwnerReferences, 1)
		assert.Equal(t, release.Name, sbom.OwnerReferences[0].Name)
	}
}

func TestName(t *testing.T) {
	assert.Equal(t, "0.0.1-app", Name("0.0.1", "app"))
	// Image keys which are not valid object names fallback to a hash.
	assert.Regexp(t, `^0\.0\.1-[a-z0-9]+$`, Name("0.0.1", "My_Image"))
}
