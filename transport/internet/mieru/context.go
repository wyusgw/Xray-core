package mieru

import (
	"context"
)

// Not proxy/mieru's account type: proxy/mieru imports this package.
type User struct {
	Name     string
	Password string
}

type UserManager interface {
	MieruUsers() []User

	SetMieruUserObserver(observer func([]User))
}

type ServerSettings struct {
	Transport string

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
