package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

type TokenValidationError struct {
	err string
}

func NewTokenValidationError(err string) *TokenValidationError {
	return &TokenValidationError{err: err}
}

func (t *TokenValidationError) Error() string {
	return t.err
}

type TokenOption struct {
	Secret    string
	StartTime int64
	EndTime   int64
	LifeTime  time.Duration
	IP        net.IP
	StreamId  string
	VodId     string
}

func (t *TokenOption) validate() error {
	if t.Secret == "" {
		return NewTokenValidationError("Secret must be provided to generate a token.")
	}

	if t.StreamId == "" {
		return NewTokenValidationError("Stream ID must be provided to generate a token.")
	}

	if t.StartTime == 0 {
		t.StartTime = time.Now().Unix()
	}

	if t.EndTime == 0 {
		t.EndTime = t.StartTime + int64(t.LifeTime.Seconds())
	}

	if t.StartTime >= t.EndTime {
		return NewTokenValidationError("Token start time is equal to or after expiration time.")
	}

	return nil
}

func (t *TokenOption) publicPayload() string {
	var arr []string
	if t.IP != nil {
		arr = append(arr, fmt.Sprintf("ip=%v", t.IP.String()))
	}
	arr = append(arr, fmt.Sprintf("st=%v", t.StartTime))
	if t.VodId != "" {
		arr = append(arr, fmt.Sprintf("vod=%v", t.VodId))
	}
	arr = append(arr, fmt.Sprintf("exp=%v", t.EndTime))
	return strings.Join(arr, "~")
}

func (t *TokenOption) payload() string {
	// format = ip=$ip~st=$start_time~vod=$vod~exp=$end_time=$stream_id=$stream_id
	return fmt.Sprintf("%v~%v", t.publicPayload(), fmt.Sprintf("stream_id=%v", t.StreamId))
}

type TokenGenerator interface {
	Generate(option TokenOption) (string, error)
}

type TokenGeneratorImpl struct {
	option *TokenOption
}

func NewTokenGenerator(option *TokenOption) *TokenGeneratorImpl {
	return &TokenGeneratorImpl{option: option}
}

func (t *TokenGeneratorImpl) Generate() (string, error) {
	if err := t.option.validate(); err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, []byte(t.option.Secret))
	h.Write([]byte(t.option.payload()))
	token := hex.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("hdnts=%v~hmac=%v", t.option.publicPayload(), token), nil
}

func main() {
	ip := flag.String("i", "", "ip address <optional>")
	startTime := flag.Int64("s", 0, "start time in unix epoch <optional>")
	lifeTime := flag.Int64("l", 0, "expiration time in second <optional>")
	endTime := flag.Int64("e", 0, "end time in unix epoch <optional>")
	streamId := flag.String("u", "", "stream id")
	secret := flag.String("k", "", "secret key")
	vodId := flag.String("v", "", "vodId stream id <optional>")

	flag.Parse()
	tokenGenerator := NewTokenGenerator(&TokenOption{
		Secret:    *secret,
		StartTime: *startTime,
		EndTime:   *endTime,
		LifeTime:  time.Duration(*lifeTime) * time.Second,
		IP:        net.ParseIP(*ip),
		StreamId:  *streamId,
		VodId:     *vodId,
	})

	res, err := tokenGenerator.Generate()

	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(res)
}
