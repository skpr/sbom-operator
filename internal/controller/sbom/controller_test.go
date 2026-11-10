package sbom

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1beta1 "github.com/skpr/sbom-operator/apis/security/v1beta1"
)

func TestReconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, clientgoscheme.AddToScheme(scheme))
	assert.NoError(t, securityv1beta1.AddToScheme(scheme))

	sbom := &securityv1beta1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "0.0.1-app",
			Namespace: "project-a",
			UID:       "4f8c1e2a-7b3d-4c5e-9a1f-2d6b8e0c3a7f",
		},
		Spec: securityv1beta1.SBOMSpec{
			Image: "example.com/app:0.0.1-app",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sbom).
		WithStatusSubresource(&securityv1beta1.SBOM{}, &corev1.Pod{}).
		Build()

	reconciler := Reconciler{
		Client: client,
		Params: Params{
			Cluster:        "test",
			Namespace:      "sbom-system",
			ServiceAccount: "sbom-scanner",
			Image:          "example.com/sbom:latest",
			Bucket:         "bucket",
			Prefix:         "sbom",
			Region:         "ap-southeast-2",
			NodeSelector: map[string]string{
				"workload": "batch",
			},
		},
	}

	request := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      sbom.Name,
			Namespace: sbom.Namespace,
		},
	}

	_, err := reconciler.Reconcile(context.TODO(), request)
	assert.NoError(t, err)

	pod := &corev1.Pod{}
	podKey := types.NamespacedName{
		Name:      PodName(sbom),
		Namespace: reconciler.Params.Namespace,
	}

	err = client.Get(context.TODO(), podKey, pod)
	assert.NoError(t, err)

	assert.Equal(t, "sbom-scanner", pod.Spec.ServiceAccountName)
	assert.Equal(t, map[string]string{"workload": "batch"}, pod.Spec.NodeSelector)
	assert.Equal(t, sbom.Namespace, pod.Annotations[AnnotationNamespace])
	assert.Equal(t, sbom.Name, pod.Annotations[AnnotationName])
	assert.Equal(t, sbom.Spec.Image, pod.Spec.Volumes[0].Image.Reference)
	assert.Equal(t, []string{ScannerCommand}, pod.Spec.Containers[0].Command)
	assert.Contains(t, pod.Spec.Containers[0].Args, "--key=sbom/test/project-a/0.0.1-app/"+Hash(sbom)+".cdx.json.gz")

	err = client.Get(context.TODO(), request.NamespacedName, sbom)
	assert.NoError(t, err)
	assert.Contains(t, sbom.Finalizers, FinalizerName)
	assert.Equal(t, securityv1beta1.PhaseInProgress, sbom.Status.Phase)
	assert.Empty(t, sbom.Status.Location)

	// Mark the Pod as complete and check the status is updated.
	pod.Status = corev1.PodStatus{
		Phase: corev1.PodSucceeded,
		ContainerStatuses: []corev1.ContainerStatus{
			{
				Name: ContainerScanner,
				State: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						Message: `{"packages":42}`,
					},
				},
			},
		},
	}
	err = client.Status().Update(context.TODO(), pod)
	assert.NoError(t, err)

	_, err = reconciler.Reconcile(context.TODO(), request)
	assert.NoError(t, err)

	err = client.Get(context.TODO(), request.NamespacedName, sbom)
	assert.NoError(t, err)
	assert.Equal(t, securityv1beta1.PhaseCompleted, sbom.Status.Phase)
	assert.Equal(t, "s3://bucket/sbom/test/project-a/0.0.1-app/"+Hash(sbom)+".cdx.json.gz", sbom.Status.Location)
	assert.Equal(t, 42, sbom.Status.Packages)

	// Deleting the SBOM should cleanup the Pod.
	err = client.Delete(context.TODO(), sbom)
	assert.NoError(t, err)

	_, err = reconciler.Reconcile(context.TODO(), request)
	assert.NoError(t, err)

	err = client.Get(context.TODO(), podKey, pod)
	assert.True(t, kerrors.IsNotFound(err))

	err = client.Get(context.TODO(), request.NamespacedName, sbom)
	assert.True(t, kerrors.IsNotFound(err))
}

func TestHash(t *testing.T) {
	a := &securityv1beta1.SBOM{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "project-a", UID: "a"}}
	b := &securityv1beta1.SBOM{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "project-a", UID: "b"}}

	// A recreated SBOM has a new UID, so it must not reuse the previous Pod or document.
	assert.NotEqual(t, PodName(a), PodName(b))
	assert.Equal(t, PodName(a), PodName(a.DeepCopy()))
	assert.Len(t, Hash(a), 16)
	assert.Equal(t, "sbom/test/project-a/app/"+Hash(a)+".cdx.json.gz", Key("sbom", "test", "project-a", "app", Hash(a)))
}

func TestFindSBOM(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				AnnotationNamespace: "project-a",
				AnnotationName:      "0.0.1-app",
			},
		},
	}

	requests := findSBOM(context.TODO(), pod)
	assert.Len(t, requests, 1)
	assert.Equal(t, types.NamespacedName{Namespace: "project-a", Name: "0.0.1-app"}, requests[0].NamespacedName)

	// Pods which were not created by this controller are ignored.
	assert.Empty(t, findSBOM(context.TODO(), &corev1.Pod{}))
}
