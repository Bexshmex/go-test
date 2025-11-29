package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// --- In-Memory Database ---

type User struct {
	Username string
	Password string
}

type Order struct {
	ID            string
	Price         int64
	Quantity      int64
	DeliveryStart int64
	DeliveryEnd   int64
	Owner         string // Username
	Status        string // "OPEN", "FILLED", "CANCELLED"
	Side          string // "buy" or "sell"
	Version       int    // 1 or 2
	Timestamp     int64  // Time of submission (Created At)
}

type Trade struct {
	ID        string
	BuyerID   string
	SellerID  string
	Price     int64
	Quantity  int64
	Timestamp int64
}

var (
	mu           sync.RWMutex
	users              = make(map[string]User)
	tokens             = make(map[string]string)
	dnaSamples         = make(map[string][]string)
	orders             = make(map[string]*Order)
	trades             = make([]*Trade, 0)
	orderCounter int64 = 0
)

// --- GalacticBuf Protocol Constants ---

const (
	ProtoV1 = 0x01
	ProtoV2 = 0x02

	TypeInt    = 0x01
	TypeString = 0x02
	TypeList   = 0x03
	TypeObject = 0x04
	TypeBytes  = 0x05
)

type GValue interface{}

// --- Encoder (Always V2) ---

func EncodeMessage(data map[string]GValue) ([]byte, error) {
	bodyBuffer := new(bytes.Buffer)
	if err := writeFieldsV2(bodyBuffer, data); err != nil {
		return nil, err
	}
	bodyBytes := bodyBuffer.Bytes()

	header := new(bytes.Buffer)
	header.WriteByte(ProtoV2)
	header.WriteByte(byte(len(data)))
	totalLen := 6 + len(bodyBytes)
	binary.Write(header, binary.BigEndian, uint32(totalLen))

	return append(header.Bytes(), bodyBytes...), nil
}

func writeFieldsV2(buf *bytes.Buffer, data map[string]GValue) error {
	for name, val := range data {
		if len(name) > 255 {
			return fmt.Errorf("field name too long")
		}
		buf.WriteByte(byte(len(name)))
		buf.WriteString(name)

		switch v := val.(type) {
		case int64:
			buf.WriteByte(TypeInt)
			binary.Write(buf, binary.BigEndian, v)
		case int:
			buf.WriteByte(TypeInt)
			binary.Write(buf, binary.BigEndian, int64(v))
		case string:
			buf.WriteByte(TypeString)
			binary.Write(buf, binary.BigEndian, uint32(len(v)))
			buf.WriteString(v)
		case []byte:
			buf.WriteByte(TypeBytes)
			binary.Write(buf, binary.BigEndian, uint32(len(v)))
			buf.Write(v)
		case []map[string]GValue:
			buf.WriteByte(TypeList)
			buf.WriteByte(TypeObject)
			binary.Write(buf, binary.BigEndian, uint32(len(v)))
			for _, obj := range v {
				buf.WriteByte(byte(len(obj)))
				if err := writeFieldsV2(buf, obj); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unsupported type for encoding: %T", v)
		}
	}
	return nil
}

// --- Decoder (Dispatcher V1/V2) ---

func DecodeMessage(r io.Reader) (map[string]GValue, error) {
	versionByte := make([]byte, 1)
	if _, err := io.ReadFull(r, versionByte); err != nil {
		if err == io.EOF {
			return nil, err
		}
		return nil, err
	}

	if versionByte[0] == ProtoV1 {
		return decodeV1(r)
	} else if versionByte[0] == ProtoV2 {
		return decodeV2(r)
	} else {
		return nil, fmt.Errorf("unknown protocol version: 0x%x", versionByte[0])
	}
}

// V1 Logic
func decodeV1(r io.Reader) (map[string]GValue, error) {
	headerRem := make([]byte, 3)
	if _, err := io.ReadFull(r, headerRem); err != nil {
		return nil, err
	}
	fieldCount := int(headerRem[0])
	return readFieldsV1(r, fieldCount)
}

func readFieldsV1(r io.Reader, count int) (map[string]GValue, error) {
	result := make(map[string]GValue)
	for i := 0; i < count; i++ {
		var nameLen uint8
		if err := binary.Read(r, binary.BigEndian, &nameLen); err != nil {
			return nil, err
		}
		nameBytes := make([]byte, nameLen)
		if _, err := io.ReadFull(r, nameBytes); err != nil {
			return nil, err
		}
		fieldName := string(nameBytes)

		var typeInd uint8
		if err := binary.Read(r, binary.BigEndian, &typeInd); err != nil {
			return nil, err
		}

		val, err := readValueV1(r, typeInd)
		if err != nil {
			return nil, err
		}
		result[fieldName] = val
	}
	return result, nil
}

func readValueV1(r io.Reader, typeInd uint8) (GValue, error) {
	switch typeInd {
	case TypeInt:
		var v int64
		if err := binary.Read(r, binary.BigEndian, &v); err != nil {
			return nil, err
		}
		return v, nil
	case TypeString:
		var l uint16
		if err := binary.Read(r, binary.BigEndian, &l); err != nil {
			return nil, err
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf), nil
	case TypeList:
		var elemType uint8
		binary.Read(r, binary.BigEndian, &elemType)
		var count uint16
		binary.Read(r, binary.BigEndian, &count)
		list := make([]GValue, 0, count)
		for k := 0; k < int(count); k++ {
			if elemType == TypeObject {
				var fc uint8
				binary.Read(r, binary.BigEndian, &fc)
				obj, _ := readFieldsV1(r, int(fc))
				list = append(list, obj)
			} else {
				v, _ := readValueV1(r, elemType)
				list = append(list, v)
			}
		}
		return list, nil
	case TypeObject:
		var fc uint8
		binary.Read(r, binary.BigEndian, &fc)
		return readFieldsV1(r, int(fc))
	default:
		return nil, fmt.Errorf("unknown type V1 %x", typeInd)
	}
}

// V2 Logic
func decodeV2(r io.Reader) (map[string]GValue, error) {
	headerRem := make([]byte, 5)
	if _, err := io.ReadFull(r, headerRem); err != nil {
		return nil, err
	}
	fieldCount := int(headerRem[0])
	return readFieldsV2(r, fieldCount)
}

func readFieldsV2(r io.Reader, count int) (map[string]GValue, error) {
	result := make(map[string]GValue)
	for i := 0; i < count; i++ {
		var nameLen uint8
		if err := binary.Read(r, binary.BigEndian, &nameLen); err != nil {
			return nil, err
		}
		nameBytes := make([]byte, nameLen)
		if _, err := io.ReadFull(r, nameBytes); err != nil {
			return nil, err
		}
		fieldName := string(nameBytes)

		var typeInd uint8
		if err := binary.Read(r, binary.BigEndian, &typeInd); err != nil {
			return nil, err
		}

		val, err := readValueV2(r, typeInd)
		if err != nil {
			return nil, err
		}
		result[fieldName] = val
	}
	return result, nil
}

func readValueV2(r io.Reader, typeInd uint8) (GValue, error) {
	switch typeInd {
	case TypeInt:
		var v int64
		if err := binary.Read(r, binary.BigEndian, &v); err != nil {
			return nil, err
		}
		return v, nil
	case TypeString:
		var l uint32
		if err := binary.Read(r, binary.BigEndian, &l); err != nil {
			return nil, err
		}
		if l > 100*1024*1024 {
			return nil, fmt.Errorf("string too large")
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf), nil
	case TypeBytes:
		var l uint32
		if err := binary.Read(r, binary.BigEndian, &l); err != nil {
			return nil, err
		}
		if l > 100*1024*1024 {
			return nil, fmt.Errorf("bytes too large")
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return buf, nil
	case TypeList:
		var elemType uint8
		binary.Read(r, binary.BigEndian, &elemType)
		var count uint32
		binary.Read(r, binary.BigEndian, &count)
		if count > 100000 {
			return nil, fmt.Errorf("list too large")
		}
		list := make([]GValue, 0, count)
		for k := 0; k < int(count); k++ {
			if elemType == TypeObject {
				var fc uint8
				binary.Read(r, binary.BigEndian, &fc)
				obj, _ := readFieldsV2(r, int(fc))
				list = append(list, obj)
			} else {
				v, _ := readValueV2(r, elemType)
				list = append(list, v)
			}
		}
		return list, nil
	case TypeObject:
		var fc uint8
		binary.Read(r, binary.BigEndian, &fc)
		return readFieldsV2(r, int(fc))
	default:
		return nil, fmt.Errorf("unknown type V2 %x", typeInd)
	}
}

// --- Helpers ---

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getUserFromToken(r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return "", false
	}
	token := authHeader[7:]
	mu.RLock()
	defer mu.RUnlock()
	user, ok := tokens[token]
	return user, ok
}

func validateDNASample(s string) bool {
	if s == "" || len(s)%3 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 'C', 'G', 'A', 'T':
		default:
			return false
		}
	}
	return true
}

func splitCodons(s string) []string {
	codons := make([]string, 0, len(s)/3)
	for i := 0; i < len(s); i += 3 {
		codons = append(codons, s[i:i+3])
	}
	return codons
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func codonEditDistanceBounded(a, b []string, limit int) int {
	m := len(a)
	n := len(b)
	if limit < 0 {
		limit = 0
	}
	if absInt(m-n) > limit {
		return limit + 1
	}
	if limit == 0 {
		if m != n {
			return limit + 1
		}
		for i := range a {
			if a[i] != b[i] {
				return limit + 1
			}
		}
		return 0
	}

	inf := limit + 1
	prev := make(map[int]int, 2*limit+2)
	for j := 0; j <= n && j <= limit; j++ {
		prev[j] = j
	}

	for i := 1; i <= m; i++ {
		curr := make(map[int]int, 2*limit+2)
		startJ := i - limit
		if startJ < 0 {
			startJ = 0
		}
		endJ := i + limit
		if endJ > n {
			endJ = n
		}

		for j := startJ; j <= endJ; j++ {
			del := inf
			if v, ok := prev[j]; ok {
				del = v + 1
			}
			ins := inf
			if v, ok := curr[j-1]; ok {
				ins = v + 1
			}
			sub := inf
			if j > 0 {
				if v, ok := prev[j-1]; ok {
					sub = v
					if a[i-1] != b[j-1] {
						sub++
					}
				}
			}

			val := del
			if ins < val {
				val = ins
			}
			if sub < val {
				val = sub
			}
			if val <= limit {
				curr[j] = val
			}
		}

		if len(curr) == 0 {
			return limit + 1
		}

		minRow := inf
		for _, v := range curr {
			if v < minRow {
				minRow = v
			}
		}
		if minRow > limit {
			return limit + 1
		}
		prev = curr
	}

	if v, ok := prev[n]; ok && v <= limit {
		return v
	}
	return limit + 1
}

// Map internal order status to external API status
// OPEN -> ACTIVE, FILLED -> FILLED, others passed through
func externalStatus(status string) string {
	if status == "FILLED" {
		return "FILLED"
	}
	if status == "OPEN" {
		return "ACTIVE"
	}
	return status
}

// --- HTTP Handlers ---

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	data, err := DecodeMessage(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	username, _ := data["username"].(string)
	password, _ := data["password"].(string)

	if username == "" || password == "" {
		http.Error(w, "Empty fields", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	if _, exists := users[username]; exists {
		http.Error(w, "Conflict", http.StatusConflict)
		return
	}
	users[username] = User{Username: username, Password: password}
	w.WriteHeader(http.StatusNoContent)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	data, err := DecodeMessage(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	username, _ := data["username"].(string)
	password, _ := data["password"].(string)

	mu.Lock()
	defer mu.Unlock()
	u, exists := users[username]
	if !exists || u.Password != password {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token := generateToken()
	tokens[token] = username

	resp := map[string]GValue{"token": token}
	encoded, _ := EncodeMessage(resp)
	w.Header().Set("Content-Type", "application/x-galacticbuf")
	w.Write(encoded)
}

func passwordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	data, err := DecodeMessage(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	username, _ := data["username"].(string)
	oldPass, _ := data["old_password"].(string)
	newPass, _ := data["new_password"].(string)

	if username == "" || oldPass == "" || newPass == "" {
		http.Error(w, "Empty fields", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	u, exists := users[username]
	if !exists || u.Password != oldPass {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	u.Password = newPass
	users[username] = u

	for token, user := range tokens {
		if user == username {
			delete(tokens, token)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func dnaSubmitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	data, err := DecodeMessage(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	username, okU := data["username"].(string)
	password, okP := data["password"].(string)
	dna, okD := data["dna_sample"].(string)
	if !okU || !okP || !okD || username == "" || password == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if !validateDNASample(dna) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	u, exists := users[username]
	if !exists || u.Password != password {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	existing := dnaSamples[username]
	for _, sample := range existing {
		if sample == dna {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	dnaSamples[username] = append(existing, dna)
	w.WriteHeader(http.StatusNoContent)
}

func dnaLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	data, err := DecodeMessage(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	username, okU := data["username"].(string)
	dna, okD := data["dna_sample"].(string)
	if !okU || !okD || username == "" || dna == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if !validateDNASample(dna) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	submittedCodons := splitCodons(dna)

	mu.RLock()
	_, userExists := users[username]
	samples := dnaSamples[username]
	mu.RUnlock()

	if !userExists || len(samples) == 0 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	matched := false
	for _, ref := range samples {
		refCodons := splitCodons(ref)
		allowed := len(refCodons) / 100000
		dist := codonEditDistanceBounded(refCodons, submittedCodons, allowed)
		if dist <= allowed {
			matched = true
			break
		}
	}

	if !matched {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token := generateToken()
	mu.Lock()
	tokens[token] = username
	mu.Unlock()

	resp := map[string]GValue{"token": token}
	encoded, _ := EncodeMessage(resp)
	w.Header().Set("Content-Type", "application/x-galacticbuf")
	w.Write(encoded)
}

// V1 Orders Handler (V1 List & V1 Submit)
func ordersV1Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		startStr := q.Get("delivery_start")
		endStr := q.Get("delivery_end")

		if startStr == "" || endStr == "" {
			http.Error(w, "Missing query params", http.StatusBadRequest)
			return
		}

		start, err1 := strconv.ParseInt(startStr, 10, 64)
		end, err2 := strconv.ParseInt(endStr, 10, 64)
		if err1 != nil || err2 != nil {
			http.Error(w, "Invalid timestamps", http.StatusBadRequest)
			return
		}

		mu.RLock()
		var filtered []*Order
		for _, o := range orders {
			if o.Version == 1 && o.Status == "OPEN" && o.DeliveryStart == start && o.DeliveryEnd == end {
				filtered = append(filtered, o)
			}
		}
		mu.RUnlock()

		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].Price < filtered[j].Price
		})

		list := make([]map[string]GValue, 0, len(filtered))
		for _, o := range filtered {
			list = append(list, map[string]GValue{
				"order_id":       o.ID,
				"price":          o.Price,
				"quantity":       o.Quantity,
				"delivery_start": o.DeliveryStart,
				"delivery_end":   o.DeliveryEnd,
			})
		}

		resp := map[string]GValue{"orders": list}
		encoded, _ := EncodeMessage(resp)
		w.Header().Set("Content-Type", "application/x-galacticbuf")
		w.Write(encoded)
		return
	}

	if r.Method == http.MethodPost {
		username, authOk := getUserFromToken(r)
		if !authOk {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		data, err := DecodeMessage(r.Body)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		price, ok1 := data["price"].(int64)
		quantity, ok2 := data["quantity"].(int64)
		start, ok3 := data["delivery_start"].(int64)
		end, ok4 := data["delivery_end"].(int64)

		if !ok1 || !ok2 || !ok3 || !ok4 {
			http.Error(w, "Missing fields", http.StatusBadRequest)
			return
		}
		if quantity <= 0 {
			http.Error(w, "Quantity must be positive", http.StatusBadRequest)
			return
		}
		const hourMs = 3600000
		if start%hourMs != 0 || end%hourMs != 0 || end <= start || (end-start) != hourMs {
			http.Error(w, "Invalid Contract Timestamps", http.StatusBadRequest)
			return
		}

		mu.Lock()
		orderCounter++
		orderID := fmt.Sprintf("ord-%d", orderCounter)
		newOrder := &Order{
			ID:            orderID,
			Price:         price,
			Quantity:      quantity,
			DeliveryStart: start,
			DeliveryEnd:   end,
			Owner:         username,
			Status:        "OPEN",
			Side:          "sell",
			Version:       1,
			Timestamp:     time.Now().UnixMilli(),
		}
		orders[orderID] = newOrder
		mu.Unlock()

		resp := map[string]GValue{"order_id": orderID}
		encoded, _ := EncodeMessage(resp)
		w.Header().Set("Content-Type", "application/x-galacticbuf")
		w.Write(encoded)
		return
	}
}

// Helper to match order against the book
// Assumes mu is locked
func matchOrder(order *Order) int64 {
	var filledQty int64 = 0
	var matchingOrders []*Order

	// Find matching orders
	for _, o := range orders {
		if o.Version == 2 && o.Status == "OPEN" && o.DeliveryStart == order.DeliveryStart && o.DeliveryEnd == order.DeliveryEnd {
			if order.Side == "buy" && o.Side == "sell" && order.Price >= o.Price {
				matchingOrders = append(matchingOrders, o)
			} else if order.Side == "sell" && o.Side == "buy" && order.Price <= o.Price {
				matchingOrders = append(matchingOrders, o)
			}
		}
	}

	// Sort matching orders
	if order.Side == "buy" {
		sort.Slice(matchingOrders, func(i, j int) bool {
			if matchingOrders[i].Price != matchingOrders[j].Price {
				return matchingOrders[i].Price < matchingOrders[j].Price
			}
			return matchingOrders[i].Timestamp < matchingOrders[j].Timestamp
		})
	} else {
		sort.Slice(matchingOrders, func(i, j int) bool {
			if matchingOrders[i].Price != matchingOrders[j].Price {
				return matchingOrders[i].Price > matchingOrders[j].Price
			}
			return matchingOrders[i].Timestamp < matchingOrders[j].Timestamp
		})
	}

	now := time.Now().UnixMilli()

	// Execute matches
	for _, matchOrder := range matchingOrders {
		if order.Quantity <= 0 {
			break
		}

		tradeQty := order.Quantity
		if matchOrder.Quantity < tradeQty {
			tradeQty = matchOrder.Quantity
		}

		tradePrice := matchOrder.Price

		var buyerID, sellerID string
		if order.Side == "buy" {
			buyerID = order.Owner
			sellerID = matchOrder.Owner
		} else {
			buyerID = matchOrder.Owner
			sellerID = order.Owner
		}

		tradeID := fmt.Sprintf("trd-%s-%d", matchOrder.ID, now)
		newTrade := &Trade{
			ID:        tradeID,
			BuyerID:   buyerID,
			SellerID:  sellerID,
			Price:     tradePrice,
			Quantity:  tradeQty,
			Timestamp: now,
		}
		trades = append(trades, newTrade)

		order.Quantity -= tradeQty
		filledQty += tradeQty
		matchOrder.Quantity -= tradeQty

		if matchOrder.Quantity <= 0 {
			matchOrder.Status = "FILLED"
		}
	}

	if order.Quantity <= 0 {
		order.Status = "FILLED"
	}

	return filledQty
}

// V2 Orders Handler (V2 Order Book & V2 Submit)
func ordersV2Handler(w http.ResponseWriter, r *http.Request) {

	// GET /v2/orders (ORDER BOOK - Public)
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		startStr := q.Get("delivery_start")
		endStr := q.Get("delivery_end")

		if startStr == "" || endStr == "" {
			http.Error(w, "Missing query params", http.StatusBadRequest)
			return
		}

		start, err1 := strconv.ParseInt(startStr, 10, 64)
		end, err2 := strconv.ParseInt(endStr, 10, 64)
		if err1 != nil || err2 != nil {
			http.Error(w, "Invalid timestamps", http.StatusBadRequest)
			return
		}
		const hourMs = 3600000
		if start%hourMs != 0 || end%hourMs != 0 || end <= start || (end-start) != hourMs {
			http.Error(w, "Invalid Contract Timestamps", http.StatusBadRequest)
			return
		}

		mu.RLock()
		var bids []*Order
		var asks []*Order

		for _, o := range orders {
			// Filters: V2, OPEN, Match Contract
			if o.Version == 2 && o.Status == "OPEN" && o.DeliveryStart == start && o.DeliveryEnd == end {
				if o.Side == "buy" {
					bids = append(bids, o)
				} else if o.Side == "sell" {
					asks = append(asks, o)
				}
			}
		}
		mu.RUnlock()

		// --- Sorting ---

		// Bids: Price DESC (Highest First), then Time ASC (Oldest First)
		sort.Slice(bids, func(i, j int) bool {
			if bids[i].Price != bids[j].Price {
				return bids[i].Price > bids[j].Price // Highest price first
			}
			return bids[i].Timestamp < bids[j].Timestamp // Oldest time first
		})

		// Asks: Price ASC (Lowest First), then Time ASC (Oldest First)
		sort.Slice(asks, func(i, j int) bool {
			if asks[i].Price != asks[j].Price {
				return asks[i].Price < asks[j].Price // Lowest price first
			}
			return asks[i].Timestamp < asks[j].Timestamp // Oldest time first
		})

		// --- Response Construction ---

		bidsList := make([]map[string]GValue, 0, len(bids))
		for _, o := range bids {
			bidsList = append(bidsList, map[string]GValue{
				"order_id": o.ID,
				"price":    o.Price,
				"quantity": o.Quantity,
			})
		}

		asksList := make([]map[string]GValue, 0, len(asks))
		for _, o := range asks {
			asksList = append(asksList, map[string]GValue{
				"order_id": o.ID,
				"price":    o.Price,
				"quantity": o.Quantity,
			})
		}

		resp := map[string]GValue{
			"bids": bidsList,
			"asks": asksList,
		}
		encoded, _ := EncodeMessage(resp)
		w.Header().Set("Content-Type", "application/x-galacticbuf")
		w.Write(encoded)
		return
	}

	// POST /v2/orders (Submit V2 - Auth Required)
	if r.Method == http.MethodPost {
		username, authOk := getUserFromToken(r)
		if !authOk {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		data, err := DecodeMessage(r.Body)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		side, ok0 := data["side"].(string)
		price, ok1 := data["price"].(int64)
		quantity, ok2 := data["quantity"].(int64)
		start, ok3 := data["delivery_start"].(int64)
		end, ok4 := data["delivery_end"].(int64)

		if !ok0 || !ok1 || !ok2 || !ok3 || !ok4 {
			http.Error(w, "Missing fields", http.StatusBadRequest)
			return
		}

		if side != "buy" && side != "sell" {
			http.Error(w, "Invalid side", http.StatusBadRequest)
			return
		}

		if quantity <= 0 {
			http.Error(w, "Quantity must be positive", http.StatusBadRequest)
			return
		}
		const hourMs = 3600000
		if start%hourMs != 0 || end%hourMs != 0 || end <= start || (end-start) != hourMs {
			http.Error(w, "Invalid Contract Timestamps", http.StatusBadRequest)
			return
		}

		mu.Lock()
		orderCounter++
		orderID := fmt.Sprintf("ord-v2-%d", orderCounter)
		now := time.Now().UnixMilli()

		newOrder := &Order{
			ID:            orderID,
			Price:         price,
			Quantity:      quantity,
			DeliveryStart: start,
			DeliveryEnd:   end,
			Owner:         username,
			Status:        "OPEN",
			Side:          side,
			Version:       2,
			Timestamp:     now,
		}

		filledQty := matchOrder(newOrder)

		// Only insert into order book if not fully filled
		if newOrder.Status != "FILLED" {
			orders[orderID] = newOrder
		}
		mu.Unlock()

		resp := map[string]GValue{
			"order_id":        orderID,
			"status":          externalStatus(newOrder.Status),
			"filled_quantity": filledQty,
		}
		encoded, _ := EncodeMessage(resp)
		w.Header().Set("Content-Type", "application/x-galacticbuf")
		w.Write(encoded)
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func orderOperationHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/v2/orders/"):]
	if id == "" {
		ordersV2Handler(w, r)
		return
	}

	if r.Method == http.MethodPut {
		modifyOrderHandler(w, r, id)
		return
	}
	if r.Method == http.MethodDelete {
		cancelOrderHandler(w, r, id)
		return
	}
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func modifyOrderHandler(w http.ResponseWriter, r *http.Request, orderID string) {
	username, authOk := getUserFromToken(r)
	if !authOk {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	data, err := DecodeMessage(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	price, ok1 := data["price"].(int64)
	quantity, ok2 := data["quantity"].(int64)
	if !ok1 || !ok2 {
		http.Error(w, "Missing fields", http.StatusBadRequest)
		return
	}
	if quantity <= 0 {
		http.Error(w, "Quantity must be positive", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	order, exists := orders[orderID]
	if !exists || order.Status == "CANCELLED" {
		http.Error(w, "Order not found", http.StatusNotFound)
		return
	}
	if order.Status == "FILLED" {
		http.Error(w, "Order is fully filled", http.StatusNotFound)
		return
	}
	if order.Owner != username {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if order.Version != 2 {
		http.Error(w, "Order not found", http.StatusNotFound) // Only V2 orders
		return
	}

	// Update Logic
	resetPriority := false
	if price != order.Price {
		resetPriority = true
	}
	if quantity > order.Quantity {
		resetPriority = true
	}

	order.Price = price
	order.Quantity = quantity
	if resetPriority {
		now := time.Now().UnixMilli()
		if now <= order.Timestamp {
			now = order.Timestamp + 1
		}
		order.Timestamp = now
	}

	filledQty := matchOrder(order)

	resp := map[string]GValue{
		"order_id":        orderID,
		"status":          externalStatus(order.Status),
		"filled_quantity": filledQty,
	}
	encoded, _ := EncodeMessage(resp)
	w.Header().Set("Content-Type", "application/x-galacticbuf")
	w.Write(encoded)
}

func cancelOrderHandler(w http.ResponseWriter, r *http.Request, orderID string) {
	username, authOk := getUserFromToken(r)
	if !authOk {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	order, exists := orders[orderID]
	if !exists || order.Status == "CANCELLED" {
		http.Error(w, "Order not found", http.StatusNotFound)
		return
	}
	if order.Status == "FILLED" {
		http.Error(w, "Order is fully filled", http.StatusNotFound)
		return
	}
	if order.Owner != username {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if order.Version != 2 {
		http.Error(w, "Order not found", http.StatusNotFound) // Only V2 orders
		return
	}

	order.Status = "CANCELLED"
	w.WriteHeader(http.StatusNoContent)
}

func myOrdersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Auth Required
	username, authOk := getUserFromToken(r)
	if !authOk {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	mu.RLock()
	// 2. Filter User's Active Orders
	var myOrders []*Order
	for _, o := range orders {
		if o.Owner == username && o.Status == "OPEN" {
			myOrders = append(myOrders, o)
		}
	}
	mu.RUnlock()

	// 3. Sort by Timestamp Descending (Newest First)
	sort.Slice(myOrders, func(i, j int) bool {
		return myOrders[i].Timestamp > myOrders[j].Timestamp
	})

	// 4. Construct Response
	list := make([]map[string]GValue, 0, len(myOrders))
	for _, o := range myOrders {
		list = append(list, map[string]GValue{
			"order_id":       o.ID,
			"side":           o.Side,
			"price":          o.Price,
			"quantity":       o.Quantity,
			"delivery_start": o.DeliveryStart,
			"delivery_end":   o.DeliveryEnd,
			"timestamp":      o.Timestamp,
		})
	}

	resp := map[string]GValue{"orders": list}
	encoded, _ := EncodeMessage(resp)
	w.Header().Set("Content-Type", "application/x-galacticbuf")
	w.Write(encoded)
}

func tradesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		mu.RLock()
		resultTrades := make([]*Trade, len(trades))
		copy(resultTrades, trades)
		mu.RUnlock()

		sort.Slice(resultTrades, func(i, j int) bool {
			return resultTrades[i].Timestamp > resultTrades[j].Timestamp
		})

		list := make([]map[string]GValue, 0, len(resultTrades))
		for _, t := range resultTrades {
			list = append(list, map[string]GValue{
				"trade_id":  t.ID,
				"buyer_id":  t.BuyerID,
				"seller_id": t.SellerID,
				"price":     t.Price,
				"quantity":  t.Quantity,
				"timestamp": t.Timestamp,
			})
		}

		resp := map[string]GValue{"trades": list}
		encoded, _ := EncodeMessage(resp)
		w.Header().Set("Content-Type", "application/x-galacticbuf")
		w.Write(encoded)
		return
	}

	if r.Method == http.MethodPost {
		buyerUser, authOk := getUserFromToken(r)
		if !authOk {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		data, err := DecodeMessage(r.Body)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		orderID, ok := data["order_id"].(string)
		if !ok {
			http.Error(w, "Missing order_id", http.StatusBadRequest)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		order, exists := orders[orderID]
		// V1 endpoint only takes V1 orders
		if !exists || order.Status != "OPEN" || order.Version != 1 {
			http.Error(w, "Order not found or inactive", http.StatusNotFound)
			return
		}

		order.Status = "FILLED"

		now := time.Now().UnixMilli()
		tradeID := fmt.Sprintf("trd-%s-%d", order.ID, now)

		newTrade := &Trade{
			ID:        tradeID,
			BuyerID:   buyerUser,
			SellerID:  order.Owner,
			Price:     order.Price,
			Quantity:  order.Quantity,
			Timestamp: now,
		}
		trades = append(trades, newTrade)

		resp := map[string]GValue{"trade_id": tradeID}
		encoded, _ := EncodeMessage(resp)
		w.Header().Set("Content-Type", "application/x-galacticbuf")
		w.Write(encoded)
	}
}

func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		next(w, r)
	}
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/user/password", passwordHandler)
	mux.HandleFunc("/dna-submit", dnaSubmitHandler)
	mux.HandleFunc("/dna-login", dnaLoginHandler)

	mux.HandleFunc("/orders", ordersV1Handler)
	mux.HandleFunc("/v2/orders", ordersV2Handler)
	mux.HandleFunc("/v2/orders/", orderOperationHandler)
	mux.HandleFunc("/v2/my-orders", myOrdersHandler)

	mux.HandleFunc("/trades", tradesHandler)

	log.Println("Galactic Exchange started on :8080")
	if err := http.ListenAndServe(":8080", loggingMiddleware(mux.ServeHTTP)); err != nil {
		log.Fatal(err)
	}
}
