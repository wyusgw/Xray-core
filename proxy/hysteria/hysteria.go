// Package hysteria is the first Hysteria generation; the second is hysteria2.
package hysteria

import (
	"strconv"

	"github.com/xtls/xray-core/common/errors"
)

//go:generate protoc -I ../.. --go_out=../.. --go_opt=paths=source_relative proxy/hysteria/config.proto

const protocolName = "hysteria"

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}

func portText(port uint16) string {
	return strconv.Itoa(int(port))
}
