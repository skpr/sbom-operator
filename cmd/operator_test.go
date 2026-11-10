package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestParseTolerations(t *testing.T) {
	tolerations, err := parseTolerations([]string{
		"dedicated=batch:NoSchedule",
		"spot:NoExecute",
		"gpu",
	})
	assert.NoError(t, err)

	assert.Equal(t, []corev1.Toleration{
		{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "batch", Effect: corev1.TaintEffectNoSchedule},
		{Key: "spot", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
		{Key: "gpu", Operator: corev1.TolerationOpExists},
	}, tolerations)

	_, err = parseTolerations([]string{"=value"})
	assert.Error(t, err)
}
