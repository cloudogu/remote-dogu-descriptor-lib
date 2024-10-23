package repository

import (
	"context"
	"github.com/cloudogu/ces-commons-lib/dogu"
	"github.com/cloudogu/cesapp-lib/core"
)

type RemoteDoguDescriptorRepository interface {
	// GetLatest returns the dogu descriptor for a dogu from the remote server.
	// NotFoundError if there is no descriptor for that dogu
	// ConnectionError if there are any connection issues
	// Generic Error if there are any other issues
	GetLatest(context.Context, dogu.QualifiedDoguName) (*core.Dogu, error)
	// Get returns a version specific dogu descriptor.
	// NotFoundError if there is no descriptor for that dogu
	// ConnectionError if there are any connection issues
	// Generic Error if there are any other issues
	Get(context.Context, dogu.QualifiedDoguVersion) (*core.Dogu, error)
}
