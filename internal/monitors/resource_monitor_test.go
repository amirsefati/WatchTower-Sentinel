package monitors

import (
	"context"
	"testing"
	"time"

	"watchtower-sentinel/internal/model"
)

type fakeSampler struct {
	values [][2]float64
	index  int
}

func (f *fakeSampler) Sample() (float64, float64, error) {
	if f.index >= len(f.values) {
		return f.values[len(f.values)-1][0], f.values[len(f.values)-1][1], nil
	}
	v := f.values[f.index]
	f.index++
	return v[0], v[1], nil
}

func TestResourceMonitorRequiresSustainedThreshold(t *testing.T) {
	sampler := &fakeSampler{
		values: [][2]float64{
			{0, 0},
			{95, 20},
			{95, 20},
			{95, 20},
			{95, 20},
			{95, 20},
		},
	}
	monitor := NewResourceMonitor(sampler, 90, 90, 40*time.Millisecond, 10*time.Millisecond)
	out := make(chan model.ResourceEvent, 10)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	go func() {
		_ = monitor.Run(ctx, out)
	}()

	select {
	case event := <-out:
		if event.Metric != "cpu" {
			t.Fatalf("Metric = %q, want cpu", event.Metric)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for sustained resource alert")
	}

	select {
	case extra := <-out:
		t.Fatalf("unexpected extra alert: %+v", extra)
	default:
	}
}

func TestResourceMonitorIgnoresShortSpike(t *testing.T) {
	sampler := &fakeSampler{
		values: [][2]float64{
			{0, 0},
			{95, 20},
			{20, 20},
			{20, 20},
		},
	}
	monitor := NewResourceMonitor(sampler, 90, 90, 40*time.Millisecond, 10*time.Millisecond)
	out := make(chan model.ResourceEvent, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	go func() {
		_ = monitor.Run(ctx, out)
	}()

	<-ctx.Done()
	select {
	case event := <-out:
		t.Fatalf("unexpected alert for short spike: %+v", event)
	default:
	}
}
