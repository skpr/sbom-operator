// Package v1beta1 is a minimal mirror of the Skpr Release API (workflow.skpr.io/v1beta1).
// Only the fields required to generate SBOMs are declared.
// +kubebuilder:object:generate=true
// +groupName=workflow.skpr.io
package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "workflow.skpr.io", Version: "v1beta1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

// ReleaseSpec defines the desired state of Release.
type ReleaseSpec struct {
	// Images which are part of the release, keyed by name.
	Images map[string]ReleaseSpecImage `json:"images"`
}

// ReleaseSpecImage is the metadata for a release image.
type ReleaseSpecImage struct {
	URI string `json:"uri"`
}

// +kubebuilder:object:root=true

// Release is a Skpr application release.
type Release struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ReleaseSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// ReleaseList contains a list of Releases.
type ReleaseList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Release `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Release{}, &ReleaseList{})
}
