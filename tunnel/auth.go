// Copyright (c) 2014 RightScale, Inc. - see LICENSE

package tunnel

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/rightscale/jwtauth"
	"github.com/rightscale/wstunnel/acl"
)

func getAuthToken(req *http.Request, cookieName string) string {
	if hdr := req.Header.Get("Authorization"); hdr != "" {
		bits := strings.SplitN(hdr, " ", 2)
		if len(bits) >= 2 {
			return bits[1]
		}
	}

	if cookieName != "" {
		cookie, _ := req.Cookie(cookieName)
		if cookie != nil {
			return cookie.Value
		}
	}

	return ""
}

func authorize(cookieName string, acl acl.Client, req *http.Request) (bool, error) {
	if acl == nil {
		// client didn't provide JWT
		return false, fmt.Errorf("authorization subsystem not initialized")
	}

	authToken := getAuthToken(req, cookieName)
	ctx := context.Background()
	ctx = jwtauth.WithToken(ctx, authToken)

	paths := [][]string{
		{"/grs/projects/60073"},
	}
	principal := "/grs/users/12853"
	privileges := []string{"cm:legacy:actor"}

	ok, err := acl.CreateAccessCheck(ctx, paths, principal, privileges)
	if err != nil {
		return false, err
	}

	return ok[0], nil
}
