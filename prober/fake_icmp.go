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
	"fmt"
	"math/rand"
	"regexp"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/icmp"

	"github.com/prometheus/blackbox_exporter/config"
)

// FailureEquipments stores recovery time of failure equipments
type FailureEquipments struct {
	recoveryTime map[string]time.Time
	config       config.FakeICMPProbe
	logger       log.Logger
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

// IsOK return if target is OK
func (s *FailureEquipments) IsOK(target string) bool {
	r, ok := s.recoveryTime[target]
	if ok { // target是失效设备
		level.Debug(s.logger).Log("msg", "target is in failure list")
		if r.After(time.Now()) { // 修复时间未到
			return false
		}
		level.Debug(s.logger).Log("msg", "but recoveryTime is over")
		delete(s.recoveryTime, target) // 修复时间已到，删除失效记录
	}

	for _, metric := range s.config.MetricsRegexp {
		matched, _ := regexp.MatchString(metric.Regexp, target)
		if matched {
			failureProbability := float64(metric.MTTR) / float64(metric.MTBF+metric.MTTR) // 失效概率 = MTTR/(MTBF+MTTR)
			p := rand.Float64()
			level.Debug(s.logger).Log("except", failureProbability, "get", p)
			if p <= failureProbability {
				// 按正态分布估算修复时间，取平均值为MTTR，标准差为MTTR/5
				recoveryTime := time.Duration(rand.NormFloat64()*float64(metric.MTTR)/5 + float64(metric.MTTR))
				s.recoveryTime[target] = time.Now().Add(recoveryTime)
				level.Debug(s.logger).Log("msg", "put target in failure list", "recoveryTime", recoveryTime)
				return false
			}
			return true
		}
	}
	return true
}

func (s FailureEquipments) String() string {
	str := fmt.Sprintf("%d[", len(s.recoveryTime))
	for k, v := range s.recoveryTime {
		str += fmt.Sprintf("%s:%v ", k, v.Sub(time.Now()))
	}
	return str + "]"
}

var failureEquipments = FailureEquipments{
	recoveryTime: make(map[string]time.Time),
}

func ProbeFakeICMP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	var (
		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_icmp_duration_seconds",
			Help: "Duration of icmp request by phase",
		}, []string{"phase"})
	)
	failureEquipments.logger = logger
	failureEquipments.config = module.FakeICMP

	for _, lv := range []string{"resolve", "setup", "rtt"} {
		durationGaugeVec.WithLabelValues(lv)
	}

	registry.MustRegister(durationGaugeVec)

	_, lookupTime, err := chooseProtocol(ctx, module.FakeICMP.IPProtocol, true, target, registry, logger)

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
	ok := failureEquipments.IsOK(target)
	level.Debug(logger).Log("failureEquipments", fmt.Sprintf("%v", failureEquipments))
	durationGaugeVec.WithLabelValues("rtt").Add(time.Since(rttStart).Seconds())
	level.Info(logger).Log("msg", "Found matching reply packet")
	return ok
}
