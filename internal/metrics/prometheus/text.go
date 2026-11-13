package prometheus

import (
	"bytes"
	"fmt"
	"io"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// TextWriter writes metrics in the Prometheus text exposition format.
type TextWriter func(w io.Writer) error

// NewTextGatherer adapts a text exposition writer to the Gatherer interface so
// metrics collected outside the Prometheus client library can be exposed by the
// same endpoint. It keeps the existing write path as the single source of
// truth for metric names and labels.
func NewTextGatherer(write TextWriter) Gatherer {
	return &textGatherer{write: write}
}

type textGatherer struct {
	write TextWriter
}

func (g *textGatherer) Gather() (families []*dto.MetricFamily, err error) {
	if g == nil || g.write == nil {
		return nil, nil
	}

	var buffer bytes.Buffer
	err = g.write(&buffer)
	if err != nil {
		return nil, fmt.Errorf("writing metrics text: %w", err)
	}
	if buffer.Len() == 0 {
		return nil, nil
	}

	parser := expfmt.TextParser{}
	parsed, err := parser.TextToMetricFamilies(&buffer)
	if err != nil {
		return nil, fmt.Errorf("parsing metrics text: %w", err)
	}
	families = make([]*dto.MetricFamily, 0, len(parsed))
	for _, family := range parsed {
		families = append(families, family)
	}
	return families, nil
}
