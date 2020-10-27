package prober

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

func TestFakeICMPAlwaysSucc(t *testing.T) {
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	if !ProbeFakeICMP(testCTX, "192.100.1.1", config.Module{FakeICMP: config.FakeICMPProbe{}}, registry, log.NewNopLogger()) {
		t.Fatalf("TCP module failed, expected success.")
	}
}

func TestFakeICMPHalfHalf(t *testing.T) {
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	module := config.Module{
		FakeICMP: config.FakeICMPProbe{
			MetricsRegexp: []config.FailureMetric{
				{Regexp: `192\.20.*`, MTBF: 10 * time.Second, MTTR: 10 * time.Second},
			},
		},
	}
	if !ProbeFakeICMP(testCTX, "192.100.1.2", module, prometheus.NewRegistry(), log.NewNopLogger()) {
		t.Fatalf("FakeICMP module failed, expected success.")
	}
	nSamples, nOK := 100, 0
	for i := 0; i < nSamples; i++ {
		if ProbeFakeICMP(testCTX, fmt.Sprintf("192.20.0.%d", i+1), module, prometheus.NewRegistry(), log.NewNopLogger()) {
			nOK++
		}
	}
	if nOK < 20 || nOK > 80 {
		t.Fatalf("FakeICMP module error to large, expected half.")
	}
}
