package networkcontrol

import (
	"sort"
	"strings"
	"time"

	"github.com/FactomProject/factom"
)

type AuthCache struct {
	interval time.Duration
	time     time.Time

	cache []*factom.Authority
}

func NewAuthCache(d time.Duration) *AuthCache {
	ac := new(AuthCache)
	ac.interval = d
	return ac
}

func (ac *AuthCache) Get() ([]*factom.Authority, error) {
	if time.Since(ac.time) < ac.interval {
		return ac.cache, nil
	}

	auth, err := factom.GetAuthorities()
	if err != nil {
		return nil, err
	}

	sort.Slice(auth, func(i, j int) bool {
		if auth[i].Status == auth[j].Status {
			return strings.Compare(auth[i].AuthorityChainID, auth[j].AuthorityChainID) < 0
		}
		if auth[i].Status == "federated" {
			return true
		}
		return false
	})

	ac.cache = auth
	ac.time = time.Now()

	return ac.cache, nil
}

func (ac *AuthCache) GetSpecific(id string) (*factom.Authority, error) {
	cache, err := ac.Get()
	if err != nil {
		return nil, err
	}

	for _, a := range cache {
		if a.AuthorityChainID == id {
			return a, nil
		}
	}

	return nil, nil
}
