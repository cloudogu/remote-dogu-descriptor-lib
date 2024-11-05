package repository

import (
	"github.com/cloudogu/cesapp-lib/core"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewRemoteDoguDescriptorRepository(t *testing.T) {
	remoteConfig := &core.Remote{}
	credentials := &core.Credentials{}
	got, err := NewRemoteDoguDescriptorRepository(remoteConfig, credentials)

	assert.NotNil(t, got)
	assert.Nil(t, err)
}

func TestNewRemoteDoguDescriptorRepository_WithProxySettingsEnabled(t *testing.T) {
	remoteConfig := &core.Remote{
		ProxySettings: core.ProxySettings{
			Enabled:  true,
			Username: "Test",
		},
	}
	credentials := &core.Credentials{}
	got, err := NewRemoteDoguDescriptorRepository(remoteConfig, credentials)

	assert.NotNil(t, got)
	assert.Nil(t, err)
}
