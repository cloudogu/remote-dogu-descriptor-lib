package repository

import (
	"errors"
	"github.com/cloudogu/ces-commons-lib/dogu"
	"github.com/cloudogu/cesapp-lib/core"
)

var NotFoundError = errors.New("No DoguDescriptor found for that dogu")
var ConnectionError = errors.New("There are some connection issues")

func NewRemoteDoguDescriptorRepository(remoteConfig *core.Remote, credentials *core.Credentials) (dogu.RemoteDoguDescriptorRepository, error) {
	return newHTTPRemote(remoteConfig, credentials)
}
