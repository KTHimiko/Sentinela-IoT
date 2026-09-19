package main

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// ---------- response-time measurement ----------

// The evaluation criteria in the article ask for "the interval between
// detecting a device at risk and its isolation taking effect". Measured
// literally that interval includes however long the operator took to
// click, which says nothing about the artefact, so three distinct things
// are recorded instead and reported separately:
//
//   - scan duration: how long a full sweep of the subnet takes
//   - containment: from the isolation order to the firewall rule verified
//     active, which is the artefact's own cost and involves no human
//   - risk to order: from the moment a device was first classified as high
//     risk to the moment isolation was ordered; today that includes human
//     decision time, and saying so is the honest way to report it
//
// Samples are kept in memory and capped: this is evidence for the
// evaluation, not a time series worth persisting.
const maxSamples = 200

var metricsMu sync.Mutex
var scanSamples []time.Duration
var containmentSamples []time.Duration
var riskToOrderSamples []time.Duration
var highRiskSince = map[string]time.Time{}

func addSample(list *[]time.Duration, d time.Duration) {
	*list = append(*list, d)
	if len(*list) > maxSamples {
		*list = (*list)[len(*list)-maxSamples:]
	}
}

// recordScanDuration stores how long one full scan cycle took.
func recordScanDuration(d time.Duration) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	addSample(&scanSamples, d)
}

// noteRiskLevel keeps track of since when each device has been classified
// as high risk, which is the starting point of the response interval. A
// device that drops below high risk, or leaves the network, has its mark
// cleared so a later spike is measured from the new occurrence and not
// from an old one.
func noteRiskLevel(results []deviceResult) {
	metricsMu.Lock()
	defer metricsMu.Unlock()

	present := make(map[string]bool, len(results))
	for _, r := range results {
		present[r.IP] = true
		if r.Risk != "alto" || r.Trusted {
			delete(highRiskSince, r.IP)
			continue
		}
		if _, marked := highRiskSince[r.IP]; !marked {
			highRiskSince[r.IP] = time.Now()
		}
	}
	for ip := range highRiskSince {
		if !present[ip] {
			delete(highRiskSince, ip)
		}
	}
}

// recordContainment stores the artefact's own containment cost and, when
// the device had already been flagged as high risk, how long it took from
// that flag to the order being given.
func recordContainment(ip string, orderedAt, effectiveAt time.Time) {
	metricsMu.Lock()
	since, flagged := highRiskSince[ip]
	metricsMu.Unlock()

	containment := effectiveAt.Sub(orderedAt)

	metricsMu.Lock()
	addSample(&containmentSamples, containment)
	if flagged {
		addSample(&riskToOrderSamples, orderedAt.Sub(since))
	}
	metricsMu.Unlock()

	detail := fmt.Sprintf("Contenção efetivada em %s (da ordem até a regra confirmada ativa no iptables)", formatDuration(containment))
	if flagged {
		detail += fmt.Sprintf("; o dispositivo estava marcado como risco alto havia %s", formatDuration(orderedAt.Sub(since)))
	}
	recordEvent("metrica_contencao", ip, detail)
}

// summary is the min/median/max of a set of samples.
type summary struct {
	Count            int
	Min, Median, Max time.Duration
}

func summarize(samples []time.Duration) summary {
	if len(samples) == 0 {
		return summary{}
	}
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return summary{
		Count:  len(sorted),
		Min:    sorted[0],
		Median: sorted[len(sorted)/2],
		Max:    sorted[len(sorted)-1],
	}
}

func metricsSnapshot() (scan, containment, riskToOrder summary) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	return summarize(scanSamples), summarize(containmentSamples), summarize(riskToOrderSamples)
}

// formatDuration prints a duration at a resolution a reader can use:
// milliseconds for the fast paths, seconds and minutes for the slow ones.
func formatDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1f s", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%.1f min", d.Minutes())
	default:
		return fmt.Sprintf("%.1f h", d.Hours())
	}
}
