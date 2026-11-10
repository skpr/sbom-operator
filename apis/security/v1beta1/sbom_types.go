package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Phase of the SBOM generation.
type Phase string

const (
	// PhaseInProgress when the SBOM is being generated.
	PhaseInProgress Phase = "InProgress"
	// PhaseCompleted when the SBOM has been generated and stored.
	PhaseCompleted Phase = "Completed"
	// PhaseFailed when the SBOM could not be generated.
	PhaseFailed Phase = "Failed"
	// PhaseUnknown when the state of the generation cannot be determined.
	PhaseUnknown Phase = "Unknown"
)

// IsFinished returns true if the phase will not change.
func (p Phase) IsFinished() bool {
	return p == PhaseCompleted || p == PhaseFailed
}

// SBOMSpec defines the desired state of SBOM.
type SBOMSpec struct {
	// Image which will be mounted and scanned to generate the SBOM.
	Image string `json:"image"`
}

// SBOMStatus defines the observed state of SBOM.
type SBOMStatus struct {
	// ID of the Pod which generated the SBOM.
	ID string `json:"id,omitempty"`
	// Phase of the SBOM generation.
	Phase Phase `json:"phase,omitempty"`
	// Location of the SBOM document eg. s3://bucket/sbom/cluster/namespace/name/sha.cdx.json.gz
	Location string `json:"location,omitempty"`
	// Packages which were discovered when generating the SBOM.
	Packages int `json:"packages,omitempty"`
	// StartTime of the SBOM generation.
	StartTime *metav1.Time `json:"startTime,omitempty"`
	// CompletionTime of the SBOM generation.
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Image",type=string,JSONPath=`.spec.image`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Packages",type=integer,JSONPath=`.status.packages`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SBOM is the Schema for the sboms API.
type SBOM struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SBOMSpec   `json:"spec,omitempty"`
	Status SBOMStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SBOMList contains a list of SBOMs.
type SBOMList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SBOM `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SBOM{}, &SBOMList{})
}
