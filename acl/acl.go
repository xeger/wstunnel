package acl

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/goadesign/goa"
	goaclient "github.com/goadesign/goa/client"
	"github.com/inconshreveable/log15"
	"github.com/pkg/errors"
	aclpkg "github.com/rightscale/acl/generated/client"
	"github.com/rightscale/jwtauth"
)

type (
	// Client is an interface that allows ACL clients to avoid dealing
	// with ACL client data structures and errors. It has a real implementation
	// defined in this package and may also have various test implementations
	// useful for mocking or other test purposes.
	Client interface {
		Healthy(ctx context.Context) error
		CreateAccessCheck(ctx context.Context, paths [][]string, principal string, privileges []string) ([]bool, error)
	}

	// httpClient implements Client for the purpose of communicating
	// with the real ACL service.
	realClient struct {
		inner aclClientPackageInterface
	}

	// aclClientPackageInterface is used only to define the expected acl client
	// package interface which we verify.
	aclClientPackageInterface interface {
		HealthCheckHealthCheck(ctx context.Context, path string) (*http.Response, error)
		CreateAccessCheck(ctx context.Context, path string, payload *aclpkg.CreateAccessCheckPayload) (*http.Response, error)
		DecodeRightscaleAclAccessCheckCollection(*http.Response) (aclpkg.RightscaleAclAccessCheckCollection, error)
	}
)

// TODO teach acl service to eat rsauth tokens; limit this hack to just api-version
type jwtHack struct {
	cli goaclient.Doer
}

func (jh *jwtHack) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	req.Header.Set("X-Api-Version", "2.0")
	if jwt := jwtauth.ContextToken(ctx); jwt != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwt))
	}
	return jh.cli.Do(ctx, req)
}

// NewClient creates a new acl Client
func NewClient(url *url.URL, debug bool) Client {
	doer := &jwtHack{goaclient.HTTPClientDoer(http.DefaultClient)}
	acl := aclpkg.New(doer)
	acl.Host = url.Host
	acl.Scheme = url.Scheme
	acl.Dump = debug

	return &realClient{acl}
}

// Healthy tries to contact the acl Service and returns nil if it succeeds.
func (c *realClient) Healthy(ctx context.Context) error {
	resp, err := c.inner.HealthCheckHealthCheck(ctx, aclpkg.HealthCheckHealthCheckPath())
	if err != nil {
		return errors.WithMessage(err, "Healthy call failed")
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	default:
		return c.handleError(ctx, resp)
	}
}

func (c *realClient) CreateAccessCheck(ctx context.Context, paths [][]string, principal string, privileges []string) ([]bool, error) {
	path := aclpkg.CreateAccessCheckPath()
	payload := aclpkg.CreateAccessCheckPayload{
		Paths:      paths,
		Principal:  &aclpkg.PrincipalRefType{Href: principal},
		Privileges: privileges,
	}

	resp, err := c.inner.CreateAccessCheck(ctx, path, &payload)
	if err != nil {
		return nil, errors.WithMessage(err, "IndexBillingCenters failed")
	}

	defer resp.Body.Close()
	out := make([]bool, len(paths))

	switch resp.StatusCode {
	case http.StatusOK:
		res, err := c.inner.DecodeRightscaleAclAccessCheckCollection(resp)
		if err != nil {
			return nil, err
		}

		for i, o := range res {
			out[i] = o.Authorized
		}

		return out, nil
	case http.StatusNotFound:
		c.handleError(ctx, resp)
		return out, nil // still zero valued
	default:
		return nil, c.handleError(ctx, resp)
	}
}

func (c *realClient) handleError(ctx context.Context, resp *http.Response) error {
	body := goa.ErrorResponse{}

	data, _ := ioutil.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &body); err == nil {
		log15.Error("acl: unexpected response", "body", body)
		return fmt.Errorf("acl: unexpected response")
	}
	return fmt.Errorf("acl: malformed response")
}
