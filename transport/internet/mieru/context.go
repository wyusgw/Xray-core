package mieru

import (
	"context"
)

// User is one mieru credential pair. mieru derives a session key from the name
// and the password together, so both halves travel with the user.
//
// This deliberately is not proxy/mieru's account type: the proxy package imports
// this one for the context helpers below, so the dependency cannot run the other
// way.
type User struct {
	Name     string
	Password string
}

// UserManager is implemented by the mieru inbound. The listener reads the
// current users when it starts and subscribes for later changes, which is what
// lets the handler service add and remove users while the listener keeps
// running — mieru's Mux accepts a new user map after it has started.
type UserManager interface {
	// MieruUsers returns a snapshot of the users allowed to connect.
	MieruUsers() []User

	// SetMieruUserObserver installs the callback to invoke whenever the user set
	// changes. Passing nil detaches the current observer, which the listener does
	// on close so a stopped Mux is not kept alive by the inbound.
	SetMieruUserObserver(observer func([]User))
}

// ServerSettings are the inbound's protocol settings that the listener needs.
// They arrive through the context rather than through stream settings because
// they describe mieru itself, not the stream it is carried over.
type ServerSettings struct {
	// Transport is the underlay to accept on: "TCP" or "UDP". Empty means TCP.
	Transport string

	// MTU applies to the UDP underlay only. Zero means mieru's default.
	MTU int32
}

type userManagerContextKey struct{}
type settingsContextKey struct{}

func ContextWithUserManager(ctx context.Context, manager UserManager) context.Context {
	return context.WithValue(ctx, userManagerContextKey{}, manager)
}

func UserManagerFromContext(ctx context.Context) UserManager {
	manager, _ := ctx.Value(userManagerContextKey{}).(UserManager)
	return manager
}

func ContextWithServerSettings(ctx context.Context, settings ServerSettings) context.Context {
	return context.WithValue(ctx, settingsContextKey{}, settings)
}

func ServerSettingsFromContext(ctx context.Context) ServerSettings {
	settings, _ := ctx.Value(settingsContextKey{}).(ServerSettings)
	return settings
}
