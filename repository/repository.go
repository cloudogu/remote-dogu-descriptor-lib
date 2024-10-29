package repository

import (
	"github.com/cloudogu/ces-commons-lib/dogu"
	"github.com/cloudogu/cesapp-lib/core"
)

func NewRemoteDoguDescriptorRepository(remoteConfig *core.Remote, credentials *core.Credentials) (dogu.RemoteDoguDescriptorRepository, error) {
	return newHTTPRemote(remoteConfig, credentials)
}
