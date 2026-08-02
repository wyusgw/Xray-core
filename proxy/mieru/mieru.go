package mieru

import (
	"github.com/xtls/xray-core/common/errors"
)

// Regenerates config.pb.go after config.proto changes. Run it with
// `go generate ./proxy/mieru/` from the repository root; it needs protoc and a
// protoc-gen-go on PATH (`go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11`).
//
// Only the mieru proto is regenerated on purpose: `infra/vprotogen` walks every
// .proto in the tree, and a protoc newer than the one that produced the
// committed files rewrites all of them.
//go:generate protoc -I ../.. --go_out=../.. --go_opt=paths=source_relative proxy/mieru/config.proto

const protocolName = "mieru"

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}
