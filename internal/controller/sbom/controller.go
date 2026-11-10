// Package sbom reconciles SBOM objects by running a Pod which scans the image and stores the result.
package sbom

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1beta1 "github.com/skpr/sbom-operator/apis/security/v1beta1"
)

const (
	// ControllerName is used to identify this controller in logs and events.
	ControllerName = "sbom"

	// FinalizerName for cleaning up the Pod, which lives in a different namespace to the SBOM.
	FinalizerName = "security.skpr.io/sbom"

	// Prefix which is applied to objects created.
	Prefix = "sbom"

	// AnnotationNamespace is applied to the Pod to identify the SBOM namespace.
	AnnotationNamespace = "security.skpr.io/sbom-namespace"
	// AnnotationName is applied to the Pod to identify the SBOM name.
	AnnotationName = "security.skpr.io/sbom-name"

	// AnnotationClusterAutoscalerSafeToEvict stops the cluster autoscaler from evicting the Pod.
	AnnotationClusterAutoscalerSafeToEvict = "cluster-autoscaler.kubernetes.io/safe-to-evict"
	// AnnotationKarpenterDoNotDisrupt stops Karpenter from disrupting the Pod.
	AnnotationKarpenterDoNotDisrupt = "karpenter.sh/do-not-disrupt"

	// ContainerScanner for querying the "scanner" container.
	ContainerScanner = "scanner"

	// MountScanName for mounting the image which will be scanned.
	MountScanName = "scan"
	// MountScanPath for mounting the image which will be scanned.
	MountScanPath = "/scan"

	// MountTmpName for temporary files written during the scan.
	MountTmpName = "tmp"
	// MountTmpPath for temporary files written during the scan.
	MountTmpPath = "/tmp"
)

// Reconciler reconciles a SBOM object.
type Reconciler struct {
	client.Client
	Params Params
}

// Params for this reconciler.
type Params struct {
	// Cluster name used when storing the SBOM.
	Cluster string
	// Namespace where the Pods which generate the SBOMs are run.
	Namespace string
	// ServiceAccount which has access to write to the S3 bucket.
	ServiceAccount string
	// Image which generates the SBOM.
	Image string
	// Bucket where the SBOMs are stored.
	Bucket string
	// Prefix applied to keys stored in the bucket.
	Prefix string
	// Region where the bucket resides.
	Region string
	// Endpoint override for S3 compatible storage.
	Endpoint string
	// NodeSelector applied to the Pod.
	NodeSelector map[string]string
	// Tolerations applied to the Pod.
	Tolerations []corev1.Toleration
	// ActiveDeadlineSeconds before the Pod is marked as failed.
	ActiveDeadlineSeconds int64
	// Resources which will be applied to the container generating the SBOM.
	Resources corev1.ResourceRequirements
}

// TerminationMessage written by the scanner container when it completes.
type TerminationMessage struct {
	Packages int `json:"packages"`
}

// +kubebuilder:rbac:groups=security.skpr.io,resources=sboms,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.skpr.io,resources=sboms/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.skpr.io,resources=sboms/finalizers,verbs=update
// +kubebuilder:rbac:groups="",namespace=sbom-system,resources=pods,verbs=get;list;watch;create;delete

// Reconcile implements Reconciler.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	sbom := &securityv1beta1.SBOM{}

	if err := r.Get(ctx, req.NamespacedName, sbom); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !sbom.DeletionTimestamp.IsZero() {
		if err := r.cleanup(ctx, sbom); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to cleanup: %w", err)
		}

		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(sbom, FinalizerName) {
		controllerutil.AddFinalizer(sbom, FinalizerName)

		if err := r.Update(ctx, sbom); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	if sbom.Status.Phase.IsFinished() {
		return ctrl.Result{}, nil
	}

	status, err := r.syncPod(ctx, sbom)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to sync Pod: %w", err)
	}

	if equality.Semantic.DeepEqual(sbom.Status, status) {
		return ctrl.Result{}, nil
	}

	logger.Info("Updating status", "phase", status.Phase, "location", status.Location, "packages", status.Packages)

	sbom.Status = status

	if err := r.Status().Update(ctx, sbom); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update status: %w", err)
	}

	return ctrl.Result{}, nil
}

// Helper function to delete the Pod and remove the finalizer.
func (r *Reconciler) cleanup(ctx context.Context, sbom *securityv1beta1.SBOM) error {
	if !controllerutil.ContainsFinalizer(sbom, FinalizerName) {
		return nil
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PodName(sbom),
			Namespace: r.Params.Namespace,
		},
	}

	if err := r.Delete(ctx, pod); client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("failed to delete Pod: %w", err)
	}

	controllerutil.RemoveFinalizer(sbom, FinalizerName)

	return r.Update(ctx, sbom)
}

// Helper function to sync the Pod.
func (r *Reconciler) syncPod(ctx context.Context, sbom *securityv1beta1.SBOM) (securityv1beta1.SBOMStatus, error) {
	var status securityv1beta1.SBOMStatus

	key := Key(r.Params.Prefix, r.Params.Cluster, sbom.Namespace, sbom.Name, Hash(sbom))

	args := []string{
		"scan",
		fmt.Sprintf("--path=%s", MountScanPath),
		fmt.Sprintf("--name=%s", sbom.Spec.Image),
		fmt.Sprintf("--bucket=%s", r.Params.Bucket),
		fmt.Sprintf("--key=%s", key),
	}

	if r.Params.Endpoint != "" {
		args = append(args, fmt.Sprintf("--endpoint=%s", r.Params.Endpoint))
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PodName(sbom),
			Namespace: r.Params.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "sbom-scanner",
				"app.kubernetes.io/managed-by": "sbom-operator",
			},
			Annotations: map[string]string{
				AnnotationNamespace: sbom.Namespace,
				AnnotationName:      sbom.Name,
				// https://github.com/kubernetes/autoscaler/blob/master/cluster-autoscaler/FAQ.md#what-types-of-pods-can-prevent-ca-from-removing-a-node
				AnnotationClusterAutoscalerSafeToEvict: "false",
				AnnotationKarpenterDoNotDisrupt:        "true",
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName:    r.Params.ServiceAccount,
			NodeSelector:          r.Params.NodeSelector,
			Tolerations:           r.Params.Tolerations,
			RestartPolicy:         corev1.RestartPolicyNever,
			ActiveDeadlineSeconds: ptr.To(r.Params.ActiveDeadlineSeconds),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: ptr.To(true),
				RunAsUser:    ptr.To(int64(65532)),
				RunAsGroup:   ptr.To(int64(65532)),
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
			Containers: []corev1.Container{
				{
					Name:      ContainerScanner,
					Image:     r.Params.Image,
					Resources: r.Params.Resources,
					Args:      args,
					Env: []corev1.EnvVar{
						{
							Name:  "AWS_REGION",
							Value: r.Params.Region,
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      MountScanName,
							MountPath: MountScanPath,
							ReadOnly:  true,
						},
						{
							Name:      MountTmpName,
							MountPath: MountTmpPath,
						},
					},
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: ptr.To(false),
						ReadOnlyRootFilesystem:   ptr.To(true),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
					TerminationMessagePath:   corev1.TerminationMessagePathDefault,
					TerminationMessagePolicy: corev1.TerminationMessageReadFile,
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: MountScanName,
					VolumeSource: corev1.VolumeSource{
						Image: &corev1.ImageVolumeSource{
							Reference:  sbom.Spec.Image,
							PullPolicy: corev1.PullIfNotPresent,
						},
					},
				},
				{
					Name: MountTmpName,
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
			},
		},
	}

	err := r.Create(ctx, pod)
	if err != nil && !kerrors.IsAlreadyExists(err) {
		return status, err
	}

	if err := r.Get(ctx, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, pod); err != nil {
		return status, err
	}

	status.ID = pod.Name
	status.Phase = getPhase(pod.Status)
	status.StartTime = pod.Status.StartTime
	status.CompletionTime = getCompletionTime(pod)

	if pod.Status.Phase == corev1.PodSucceeded {
		message, err := getTerminationMessage(pod)
		if err != nil {
			return status, fmt.Errorf("failed to get termination message: %w", err)
		}

		status.Location = fmt.Sprintf("s3://%s/%s", r.Params.Bucket, key)
		status.Packages = message.Packages
	}

	return status, nil
}

// Helper function to convert the Pod phase.
func getPhase(status corev1.PodStatus) securityv1beta1.Phase {
	switch status.Phase {
	case corev1.PodSucceeded:
		return securityv1beta1.PhaseCompleted
	case corev1.PodFailed:
		return securityv1beta1.PhaseFailed
	case corev1.PodUnknown:
		return securityv1beta1.PhaseUnknown
	default:
		return securityv1beta1.PhaseInProgress
	}
}

// Helper function to get the time the scanner container finished.
func getCompletionTime(pod *corev1.Pod) *metav1.Time {
	for _, container := range pod.Status.ContainerStatuses {
		if container.Name == ContainerScanner && container.State.Terminated != nil {
			return &container.State.Terminated.FinishedAt
		}
	}

	return nil
}

// Helper function to get the termination message from the scanner container.
func getTerminationMessage(pod *corev1.Pod) (TerminationMessage, error) {
	var message TerminationMessage

	for _, container := range pod.Status.ContainerStatuses {
		if container.Name != ContainerScanner || container.State.Terminated == nil {
			continue
		}

		if err := json.Unmarshal([]byte(container.State.Terminated.Message), &message); err != nil {
			return message, fmt.Errorf("failed to unmarshal: %w", err)
		}

		return message, nil
	}

	return message, fmt.Errorf("container not terminated: %s", ContainerScanner)
}

// Hash which is unique to this SBOM object.
// The UID changes when an SBOM is recreated, so a new SBOM never picks up the Pod or document of a previous one.
func Hash(sbom *securityv1beta1.SBOM) string {
	h := sha256.Sum256([]byte(sbom.UID))
	return hex.EncodeToString(h[:])[:16]
}

// PodName which is unique across all namespaces.
func PodName(sbom *securityv1beta1.SBOM) string {
	return fmt.Sprintf("%s-%s", Prefix, Hash(sbom))
}

// Key where the SBOM is stored in the bucket.
func Key(prefix, cluster, namespace, name, hash string) string {
	return path.Join(prefix, cluster, namespace, name, fmt.Sprintf("%s.cdx.json.gz", hash))
}

// SetupWithManager declares when the reconciler should be triggered.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(ControllerName).
		For(&securityv1beta1.SBOM{}).
		// Pods run in a different namespace so we cannot use an owner reference.
		Watches(
			&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(findSBOM),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
				return obj.GetNamespace() == r.Params.Namespace
			})),
		).
		Complete(r)
}

// Helper function to map a Pod back to the SBOM which created it.
func findSBOM(_ context.Context, pod client.Object) []reconcile.Request {
	annotations := pod.GetAnnotations()

	namespace, name := annotations[AnnotationNamespace], annotations[AnnotationName]
	if namespace == "" || name == "" {
		return nil
	}

	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: namespace,
				Name:      name,
			},
		},
	}
}
