package mieru

import (
	"github.com/xtls/xray-core/common/errors"
)

//go:generate protoc -I ../.. --go_out=../.. --go_opt=paths=source_relative proxy/mieru/config.proto

const protocolName = "mieru"

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}
