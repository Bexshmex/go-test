package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func resetState() {
	mu.Lock()
	defer mu.Unlock()
	users = make(map[string]User)
	tokens = make(map[string]string)
	dnaSamples = make(map[string][]string)
	orders = make(map[string]*Order)
	trades = make([]*Trade, 0)
	orderCounter = 0
}

func addOrder(o *Order) {
	mu.Lock()
	defer mu.Unlock()
	orders[o.ID] = o
}

func TestOrdersV2Get_OrderBookSortingAndFilters(t *testing.T) {
	resetState()

	const start = int64(3600000 * 100) // aligned hour boundary
	const end = start + 3600000

	// Valid V2 orders for the contract
	addOrder(&Order{ID: "bid-old-high", Version: 2, Status: "OPEN", Side: "buy", Price: 200, Quantity: 10, DeliveryStart: start, DeliveryEnd: end, Timestamp: 1})
	addOrder(&Order{ID: "bid-new-high", Version: 2, Status: "OPEN", Side: "buy", Price: 200, Quantity: 20, DeliveryStart: start, DeliveryEnd: end, Timestamp: 2})
	addOrder(&Order{ID: "bid-lower", Version: 2, Status: "OPEN", Side: "buy", Price: 150, Quantity: 30, DeliveryStart: start, DeliveryEnd: end, Timestamp: 3})

	addOrder(&Order{ID: "ask-old-low", Version: 2, Status: "OPEN", Side: "sell", Price: 40, Quantity: 5, DeliveryStart: start, DeliveryEnd: end, Timestamp: 1})
	addOrder(&Order{ID: "ask-new-low", Version: 2, Status: "OPEN", Side: "sell", Price: 40, Quantity: 6, DeliveryStart: start, DeliveryEnd: end, Timestamp: 2})
	addOrder(&Order{ID: "ask-higher", Version: 2, Status: "OPEN", Side: "sell", Price: 60, Quantity: 7, DeliveryStart: start, DeliveryEnd: end, Timestamp: 3})

	// Should be filtered out: wrong version, wrong status, wrong contract
	addOrder(&Order{ID: "v1-order", Version: 1, Status: "OPEN", Side: "buy", Price: 999, Quantity: 1, DeliveryStart: start, DeliveryEnd: end, Timestamp: 10})
	addOrder(&Order{ID: "closed-v2", Version: 2, Status: "FILLED", Side: "sell", Price: 5, Quantity: 5, DeliveryStart: start, DeliveryEnd: end, Timestamp: 11})
	addOrder(&Order{ID: "wrong-contract", Version: 2, Status: "OPEN", Side: "buy", Price: 5, Quantity: 5, DeliveryStart: start + 7200000, DeliveryEnd: end + 7200000, Timestamp: 12})

	req := httptest.NewRequest(http.MethodGet, "/v2/orders", nil)
	q := url.Values{}
	q.Set("delivery_start", "360000000")
	q.Set("delivery_end", "363600000")
	req.URL.RawQuery = q.Encode()

	rr := httptest.NewRecorder()
	ordersV2Handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	resp, err := DecodeMessage(rr.Body)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	rawBids, ok := resp["bids"].([]GValue)
	if !ok {
		t.Fatalf("bids missing or wrong type")
	}
	rawAsks, ok := resp["asks"].([]GValue)
	if !ok {
		t.Fatalf("asks missing or wrong type")
	}

	bids := make([]map[string]GValue, len(rawBids))
	for i, v := range rawBids {
		m, ok := v.(map[string]GValue)
		if !ok {
			t.Fatalf("bid element %d wrong type %T", i, v)
		}
		bids[i] = m
	}

	asks := make([]map[string]GValue, len(rawAsks))
	for i, v := range rawAsks {
		m, ok := v.(map[string]GValue)
		if !ok {
			t.Fatalf("ask element %d wrong type %T", i, v)
		}
		asks[i] = m
	}

	// Bids: price desc, then time asc
	expectedBids := []string{"bid-old-high", "bid-new-high", "bid-lower"}
	if len(bids) != len(expectedBids) {
		t.Fatalf("expected %d bids, got %d", len(expectedBids), len(bids))
	}
	for i, id := range expectedBids {
		if bids[i]["order_id"] != id {
			t.Fatalf("bids[%d] expected %s, got %v", i, id, bids[i]["order_id"])
		}
	}

	// Asks: price asc, then time asc
	expectedAsks := []string{"ask-old-low", "ask-new-low", "ask-higher"}
	if len(asks) != len(expectedAsks) {
		t.Fatalf("expected %d asks, got %d", len(expectedAsks), len(asks))
	}
	for i, id := range expectedAsks {
		if asks[i]["order_id"] != id {
			t.Fatalf("asks[%d] expected %s, got %v", i, id, asks[i]["order_id"])
		}
	}
}

func TestOrdersV2Get_InvalidContractAlignment(t *testing.T) {
	resetState()
	req := httptest.NewRequest(http.MethodGet, "/v2/orders?delivery_start=1&delivery_end=2", nil)
	rr := httptest.NewRecorder()
	ordersV2Handler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad alignment, got %d", rr.Code)
	}
}

func TestModifyOrder_PriorityAndMatching(t *testing.T) {
	resetState()
	const start = int64(3600000 * 100)
	const end = start + 3600000

	// 1. Setup: Sell order at 100
	mu.Lock()
	users["user1"] = User{Username: "user1", Password: "pw"}
	tokens["tok1"] = "user1"
	users["user2"] = User{Username: "user2", Password: "pw"}
	tokens["tok2"] = "user2"
	
	// Existing sell order
	orders["sell1"] = &Order{
		ID: "sell1", Version: 2, Status: "OPEN", Side: "sell", Price: 100, Quantity: 10,
		DeliveryStart: start, DeliveryEnd: end, Owner: "user2", Timestamp: 1000,
	}
	// Existing buy order (resting)
	orders["buy1"] = &Order{
		ID: "buy1", Version: 2, Status: "OPEN", Side: "buy", Price: 90, Quantity: 10,
		DeliveryStart: start, DeliveryEnd: end, Owner: "user1", Timestamp: 2000,
	}
	mu.Unlock()

	// 2. Modify buy1 price to 100 -> Should match sell1
	reqBody := map[string]GValue{"price": int64(100), "quantity": int64(10)}
	encoded, _ := EncodeMessage(reqBody)
	
	req := httptest.NewRequest(http.MethodPut, "/v2/orders/buy1", bytes.NewReader(encoded))
	req.Header.Set("Authorization", "Bearer tok1")
	rr := httptest.NewRecorder()
	
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/orders/", orderOperationHandler)
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	mu.Lock()
	// Check if match happened
	if len(trades) != 1 {
		t.Errorf("expected 1 trade, got %d", len(trades))
	}
	if orders["buy1"].Status != "FILLED" {
		t.Errorf("expected buy1 to be FILLED, got %s", orders["buy1"].Status)
	}
	mu.Unlock()
}

func TestModifyOrder_PriorityReset(t *testing.T) {
	resetState()
	const start = int64(3600000 * 100)
	const end = start + 3600000

	mu.Lock()
	users["u"] = User{Username: "u", Password: "p"}
	tokens["tok"] = "u"
	// Order with old timestamp
	orders["o1"] = &Order{
		ID: "o1", Version: 2, Status: "OPEN", Side: "buy", Price: 100, Quantity: 10,
		DeliveryStart: start, DeliveryEnd: end, Owner: "u", Timestamp: 1000,
	}
	mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/v2/orders/", orderOperationHandler)

	// Case 1: Decrease Quantity -> Priority Preserved
	body1, _ := EncodeMessage(map[string]GValue{"price": int64(100), "quantity": int64(5)})
	req1 := httptest.NewRequest(http.MethodPut, "/v2/orders/o1", bytes.NewReader(body1))
	req1.Header.Set("Authorization", "Bearer tok")
	rr1 := httptest.NewRecorder()
	mux.ServeHTTP(rr1, req1)

	mu.Lock()
	if orders["o1"].Timestamp != 1000 {
		t.Errorf("timestamp should be preserved on qty decrease, got %d", orders["o1"].Timestamp)
	}
	mu.Unlock()

	// Case 2: Increase Quantity -> Priority Reset
	body2, _ := EncodeMessage(map[string]GValue{"price": int64(100), "quantity": int64(20)})
	req2 := httptest.NewRequest(http.MethodPut, "/v2/orders/o1", bytes.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer tok")
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)

	mu.Lock()
	if orders["o1"].Timestamp <= 1000 {
		t.Errorf("timestamp should be reset on qty increase")
	}
	tsAfterIncrease := orders["o1"].Timestamp
	mu.Unlock()

	// Case 3: Change Price -> Priority Reset
	time.Sleep(1 * time.Millisecond) // Ensure time advances
	body3, _ := EncodeMessage(map[string]GValue{"price": int64(101), "quantity": int64(20)})
	req3 := httptest.NewRequest(http.MethodPut, "/v2/orders/o1", bytes.NewReader(body3))
	req3.Header.Set("Authorization", "Bearer tok")
	rr3 := httptest.NewRecorder()
	mux.ServeHTTP(rr3, req3)

	mu.Lock()
	if orders["o1"].Timestamp <= tsAfterIncrease {
		t.Errorf("timestamp should be reset on price change")
	}
	mu.Unlock()
}

func TestCancelOrder(t *testing.T) {
	resetState()
	mu.Lock()
	users["u"] = User{Username: "u", Password: "p"}
	tokens["tok"] = "u"
	orders["o1"] = &Order{
		ID: "o1", Version: 2, Status: "OPEN", Side: "buy", Price: 100, Quantity: 10, Owner: "u",
	}
	mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/v2/orders/", orderOperationHandler)

	// 1. Cancel Success
	req1 := httptest.NewRequest(http.MethodDelete, "/v2/orders/o1", nil)
	req1.Header.Set("Authorization", "Bearer tok")
	rr1 := httptest.NewRecorder()
	mux.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rr1.Code)
	}
	mu.Lock()
	if orders["o1"].Status != "CANCELLED" {
		t.Errorf("expected status CANCELLED, got %s", orders["o1"].Status)
	}
	mu.Unlock()

	// 2. Cancel Again -> 404
	req2 := httptest.NewRequest(http.MethodDelete, "/v2/orders/o1", nil)
	req2.Header.Set("Authorization", "Bearer tok")
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusNotFound {
		t.Errorf("expected 404 for already cancelled, got %d", rr2.Code)
	}
}
