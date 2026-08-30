package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/oknek/oknek/internal/ipc"
	"github.com/oknek/oknek/internal/routewatch"
	"github.com/oknek/oknek/internal/rules"
	"github.com/oknek/oknek/internal/store"
)

func TestCheckSocketHandler_RecordsRouteAround(t *testing.T) {
	db, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	eng := rules.NewEngine()
	eng.Register(rules.NewR10("127.0.0.1", 4000,
		[]string{"api.openai.com"}, nil, map[string]float64{"default": 0.02}))
	agg := routewatch.New(3600, 100.0, db.InsertEvent, time.Now, nil)

	h := checkSocketHandler(eng, db, agg, nil, false, nil)
	params, _ := json.Marshal(map[string]interface{}{
		"dest_host": "api.openai.com", "dest_port": 443, "process": "worker", "pid": 4821,
	})
	if _, err := h(context.Background(), &ipc.Request{Method: "check.socket", Params: params}); err != nil {
		t.Fatal(err)
	}
	st := agg.Status()
	if st.Lifetime != 1 {
		t.Fatalf("aggregator lifetime = %d, want 1", st.Lifetime)
	}
	if len(st.Processes) != 1 || st.Processes[0].Process != "worker" {
		t.Errorf("expected one 'worker' route-around, got %+v", st.Processes)
	}
}

func TestCheckSocketHandler_ViaGateway_NotRecorded(t *testing.T) {
	db, _ := store.Open(t.TempDir() + "/t.db")
	defer db.Close()
	eng := rules.NewEngine()
	eng.Register(rules.NewR10("127.0.0.1", 4000,
		[]string{"api.openai.com"}, nil, map[string]float64{"default": 0.02}))
	agg := routewatch.New(3600, 100.0, db.InsertEvent, time.Now, nil)
	h := checkSocketHandler(eng, db, agg, nil, false, nil)
	params, _ := json.Marshal(map[string]interface{}{
		"dest_host": "127.0.0.1", "dest_port": 4000, "process": "worker", "pid": 4821,
	})
	_, _ = h(context.Background(), &ipc.Request{Method: "check.socket", Params: params})
	if agg.Status().Lifetime != 0 {
		t.Error("via-gateway call must not be recorded as a route-around")
	}
}
