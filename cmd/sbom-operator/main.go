// Package main runs the operator which reconciles SBOM objects.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1beta1 "github.com/skpr/sbom-operator/apis/security/v1beta1"
	"github.com/skpr/sbom-operator/internal/controller/sbom"
)

type operatorCommand struct {
	Cluster                string
	Namespace              string
	ScannerImage           string
	ScannerServiceAccount  string
	Bucket                 string
	Prefix                 string
	Region                 string
	Endpoint               string
	NodeSelector           map[string]string
	Tolerations            []string
	ActiveDeadline         time.Duration
	RequestsCPU            string
	RequestsMemory         string
	LimitsCPU              string
	LimitsMemory           string
	MetricsBindAddress     string
	HealthProbeBindAddress string
	LeaderElect            bool
}

func (c *operatorCommand) run(_ *kingpin.ParseContext) error {
	ctrl.SetLogger(zap.New())

	logger := ctrl.Log.WithName("operator")

	scheme := runtime.NewScheme()

	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}

	if err := securityv1beta1.AddToScheme(scheme); err != nil {
		return err
	}

	tolerations, err := parseTolerations(c.Tolerations)
	if err != nil {
		return fmt.Errorf("failed to parse tolerations: %w", err)
	}

	resources, err := c.resources()
	if err != nil {
		return fmt.Errorf("failed to parse resources: %w", err)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: c.MetricsBindAddress},
		HealthProbeBindAddress: c.HealthProbeBindAddress,
		LeaderElection:         c.LeaderElect,
		LeaderElectionID:       "sbom-operator.security.skpr.io",
		Cache: cache.Options{
			// Scanner Pods only run in a single namespace.
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Pod{}: {
					Namespaces: map[string]cache.Config{
						c.Namespace: {},
					},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create manager: %w", err)
	}

	if err := (&sbom.Reconciler{
		Client: mgr.GetClient(),
		Params: sbom.Params{
			Cluster:               c.Cluster,
			Namespace:             c.Namespace,
			ServiceAccount:        c.ScannerServiceAccount,
			Image:                 c.ScannerImage,
			Bucket:                c.Bucket,
			Prefix:                c.Prefix,
			Region:                c.Region,
			Endpoint:              c.Endpoint,
			NodeSelector:          c.NodeSelector,
			Tolerations:           tolerations,
			ActiveDeadlineSeconds: int64(c.ActiveDeadline.Seconds()),
			Resources:             resources,
		},
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup controller: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("failed to setup health check: %w", err)
	}

	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("failed to setup ready check: %w", err)
	}

	logger.Info("Starting manager", "cluster", c.Cluster, "namespace", c.Namespace)

	return mgr.Start(ctrl.SetupSignalHandler())
}

// Helper function to build the scanner container resources.
func (c *operatorCommand) resources() (corev1.ResourceRequirements, error) {
	resources := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{},
		Limits:   corev1.ResourceList{},
	}

	for _, r := range []struct {
		list  corev1.ResourceList
		name  corev1.ResourceName
		value string
	}{
		{resources.Requests, corev1.ResourceCPU, c.RequestsCPU},
		{resources.Requests, corev1.ResourceMemory, c.RequestsMemory},
		{resources.Limits, corev1.ResourceCPU, c.LimitsCPU},
		{resources.Limits, corev1.ResourceMemory, c.LimitsMemory},
	} {
		if r.value == "" {
			continue
		}

		quantity, err := resource.ParseQuantity(r.value)
		if err != nil {
			return resources, fmt.Errorf("invalid %s: %w", r.name, err)
		}

		r.list[r.name] = quantity
	}

	return resources, nil
}

// Helper function to parse tolerations in the format key[=value][:effect].
func parseTolerations(values []string) ([]corev1.Toleration, error) {
	var tolerations []corev1.Toleration

	for _, value := range values {
		toleration := corev1.Toleration{
			Operator: corev1.TolerationOpExists,
		}

		if before, after, found := strings.Cut(value, ":"); found {
			toleration.Effect = corev1.TaintEffect(after)
			value = before
		}

		if before, after, found := strings.Cut(value, "="); found {
			toleration.Operator = corev1.TolerationOpEqual
			toleration.Value = after
			value = before
		}

		if value == "" {
			return nil, fmt.Errorf("toleration key is required: %q", value)
		}

		toleration.Key = value

		tolerations = append(tolerations, toleration)
	}

	return tolerations, nil
}

func main() {
	c := new(operatorCommand)

	cmd := kingpin.New("sbom-operator", "Runs the operator which reconciles SBOM objects").Action(c.run)

	cmd.Flag("cluster", "Name of the cluster, used when storing SBOMs").Envar("SBOM_CLUSTER").Required().StringVar(&c.Cluster)
	cmd.Flag("namespace", "Namespace where scanner Pods are run (typically the operator namespace)").Envar("POD_NAMESPACE").Required().StringVar(&c.Namespace)
	cmd.Flag("scanner-image", "Image used to scan (typically this image)").Envar("SBOM_SCANNER_IMAGE").Required().StringVar(&c.ScannerImage)
	cmd.Flag("scanner-service-account", "ServiceAccount used by scanner Pods, requires access to write to the bucket").Envar("SBOM_SCANNER_SERVICE_ACCOUNT").Default("sbom-scanner").StringVar(&c.ScannerServiceAccount)
	cmd.Flag("bucket", "S3 bucket where SBOMs are stored").Envar("SBOM_BUCKET").Required().StringVar(&c.Bucket)
	cmd.Flag("prefix", "Prefix applied to keys stored in the bucket").Envar("SBOM_PREFIX").Default("sbom").StringVar(&c.Prefix)
	cmd.Flag("region", "Region where the bucket resides").Envar("SBOM_REGION").StringVar(&c.Region)
	cmd.Flag("endpoint", "Endpoint override for S3 compatible storage").Envar("SBOM_ENDPOINT").StringVar(&c.Endpoint)
	cmd.Flag("node-selector", "Node selector applied to scanner Pods (key=value)").Envar("SBOM_NODE_SELECTOR").StringMapVar(&c.NodeSelector)
	cmd.Flag("toleration", "Toleration applied to scanner Pods (key[=value][:effect])").Envar("SBOM_TOLERATIONS").StringsVar(&c.Tolerations)
	cmd.Flag("active-deadline", "How long a scanner Pod can run before it is marked as failed").Envar("SBOM_ACTIVE_DEADLINE").Default("30m").DurationVar(&c.ActiveDeadline)
	cmd.Flag("requests-cpu", "CPU requested by scanner Pods").Envar("SBOM_REQUESTS_CPU").Default("100m").StringVar(&c.RequestsCPU)
	cmd.Flag("requests-memory", "Memory requested by scanner Pods").Envar("SBOM_REQUESTS_MEMORY").Default("256Mi").StringVar(&c.RequestsMemory)
	cmd.Flag("limits-cpu", "CPU limit for scanner Pods").Envar("SBOM_LIMITS_CPU").Default("1").StringVar(&c.LimitsCPU)
	cmd.Flag("limits-memory", "Memory limit for scanner Pods").Envar("SBOM_LIMITS_MEMORY").Default("1Gi").StringVar(&c.LimitsMemory)
	cmd.Flag("metrics-bind-address", "Address the metrics endpoint binds to").Envar("SBOM_METRICS_BIND_ADDRESS").Default(":8080").StringVar(&c.MetricsBindAddress)
	cmd.Flag("health-probe-bind-address", "Address the health probe endpoint binds to").Envar("SBOM_HEALTH_PROBE_BIND_ADDRESS").Default(":8081").StringVar(&c.HealthProbeBindAddress)
	cmd.Flag("leader-elect", "Enable leader election").Envar("SBOM_LEADER_ELECT").BoolVar(&c.LeaderElect)

	kingpin.MustParse(cmd.Parse(os.Args[1:]))
}
