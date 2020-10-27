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
	"gonum.org/v1/gonum/stat/distuv"
)

// EquipmentStatus stores status of equipment
type EquipmentStatus struct {
	ok        bool
	startFrom time.Time
	mtbf      float64
	mttr      float64
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func (s *EquipmentStatus) String() string {
	str := "Bad"
	if s.ok {
		str = "Good"
	}
	return fmt.Sprintf("%s %v", str, time.Now().Sub(s.startFrom)) // 处理当前状态多长时间
}

// 根据正态分布累积密度函数计算结束当前状态的概率，返回true表示当前状态不改变
func (s *EquipmentStatus) guess(logger log.Logger) bool {
	if s.mttr <= 0.0 {
		level.Debug(logger).Log("msg", "MTTR <= 0.0, always OK")
		s.ok = true
		return true
	}
	mu := s.mttr
	if s.ok {
		mu = s.mtbf
	}
	dist := distuv.Normal{
		Mu:    mu,
		Sigma: mu / 5,
	}
	elapsed := time.Now().Sub(s.startFrom)
	exceptProb := dist.CDF(float64(elapsed))
	getProb := rand.Float64()
	level.Debug(logger).Log("elapsed", elapsed, "exceptProb", exceptProb, "getProb", getProb)
	return getProb > exceptProb
}

var allStatus = make(map[string]*EquipmentStatus)

// IsOK return true if target is OK
func IsOK(target string, config config.FakeICMPProbe, logger log.Logger) bool {
	refresh := true
	status, ok := allStatus[target]
	if !ok { // 第一次访问该target
		status = &EquipmentStatus{
			mtbf: 1.0,
			mttr: 0.0,
		}
		for _, metric := range config.MetricsRegexp {
			matched, _ := regexp.MatchString(metric.Regexp, target)
			level.Debug(logger).Log("regexp", metric.Regexp, "target", target, "matched", matched)
			if matched {
				status.mtbf = float64(metric.MTBF)
				status.mttr = float64(metric.MTTR)
				break
			}
		}
	} else {
		refresh = !status.guess(logger)
	}

	if refresh {
		status.ok = rand.Float64() <= status.mtbf/(status.mttr+status.mtbf)
		status.startFrom = time.Now()
		allStatus[target] = status
	}

	level.Debug(logger).Log("target", target, "currentStatus", status)
	return status.ok
}

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
	ok := IsOK(target, module.FakeICMP, logger)
	level.Debug(logger).Log("allStatus", fmt.Sprintf("%v", allStatus))
	durationGaugeVec.WithLabelValues("rtt").Add(time.Since(rttStart).Seconds())
	level.Info(logger).Log("msg", "Found matching reply packet")
	return ok
}
