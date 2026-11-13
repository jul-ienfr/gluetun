package prometheus

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TextGatherer(t *testing.T) {
	t.Parallel()

	gatherer := NewTextGatherer(func(w io.Writer) error {
		_, err := io.WriteString(w,
			"gluetun_control_jobs_total{kind=\"switch\",state=\"committed\"} 2\n"+
				"gluetun_control_job_duration_seconds_count{kind=\"switch\"} 2\n")
		return err
	})

	families, err := gatherer.Gather()
	require.NoError(t, err)
	require.Len(t, families, 2)

	names := make([]string, 0, len(families))
	for _, family := range families {
		names = append(names, family.GetName())
	}
	assert.ElementsMatch(t,
		[]string{
			"gluetun_control_jobs_total",
			"gluetun_control_job_duration_seconds_count",
		}, names)
}

func Test_TextGatherer_Empty(t *testing.T) {
	t.Parallel()

	gatherer := NewTextGatherer(func(io.Writer) error { return nil })
	families, err := gatherer.Gather()
	require.NoError(t, err)
	assert.Empty(t, families)
}

func Test_TextGatherer_Nil(t *testing.T) {
	t.Parallel()

	families, err := NewTextGatherer(nil).Gather()
	require.NoError(t, err)
	assert.Empty(t, families)
}

func Test_TextGatherer_WriteError(t *testing.T) {
	t.Parallel()

	expected := errors.New("write failed")
	_, err := NewTextGatherer(func(io.Writer) error { return expected }).Gather()
	require.ErrorIs(t, err, expected)
}

func Test_TextGatherer_InvalidText(t *testing.T) {
	t.Parallel()

	_, err := NewTextGatherer(func(w io.Writer) error {
		_, err := io.WriteString(w, "not a metric\n")
		return err
	}).Gather()
	require.Error(t, err)
}
