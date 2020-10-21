// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/icmp"

	"github.com/prometheus/blackbox_exporter/config"
)

func ProbeFakeICMP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	var (
		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_icmp_duration_seconds",
			Help: "Duration of icmp request by phase",
		}, []string{"phase"})
	)

	for _, lv := range []string{"resolve", "setup", "rtt"} {
		durationGaugeVec.WithLabelValues(lv)
	}

	registry.MustRegister(durationGaugeVec)

	_, lookupTime, err := chooseProtocol(ctx, module.ICMP.IPProtocol, module.ICMP.IPProtocolFallback, target, registry, logger)

	if err != nil {
		level.Warn(logger).Log("msg", "Error resolving address", "err", err)
		return false
	}
	durationGaugeVec.WithLabelValues("resolve").Add(lookupTime)

	setupStart := time.Now()
	level.Info(logger).Log("msg", "Creating socket")
	var data = []byte("Prometheus Blackbox Exporter")
	body := &icmp.Echo{
		ID:   icmpID,
		Seq:  int(getICMPSequence()),
		Data: data,
	}
	level.Info(logger).Log("msg", "Creating ICMP packet", "seq", body.Seq, "id", body.ID)
	durationGaugeVec.WithLabelValues("setup").Add(time.Since(setupStart).Seconds())
	level.Info(logger).Log("msg", "Faking to Write out packet")

	rttStart := time.Now()
	level.Info(logger).Log("msg", "Waiting for reply packets")
	durationGaugeVec.WithLabelValues("rtt").Add(time.Since(rttStart).Seconds())
	level.Info(logger).Log("msg", "Found matching reply packet")
	return true
}
