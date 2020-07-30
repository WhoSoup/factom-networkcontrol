package networkcontrol

import (
	"github.com/FactomProject/factomd/common/interfaces"
	"github.com/FactomProject/factomd/state"
)

type FakeState struct {
	Authorities []interfaces.IAuthority
	state.State
}

func (fs *FakeState) GetAuthorities() []interfaces.IAuthority {
	return fs.Authorities
}
