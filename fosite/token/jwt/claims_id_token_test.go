// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/ory/hydra/v2/fosite/token/jwt"
)

func TestIDTokenAssert(t *testing.T) {
	assert.NoError(t, (&IDTokenClaims{ExpiresAt: time.Now().UTC().Add(time.Hour)}).
		ToMapClaims().Valid())
	assert.Error(t, (&IDTokenClaims{ExpiresAt: time.Now().UTC().Add(-time.Hour)}).
		ToMapClaims().Valid())

	assert.NotEmpty(t, (new(IDTokenClaims)).ToMapClaims()["jti"])
}

func TestIDTokenClaimsToMap(t *testing.T) {
	idTokenClaims := &IDTokenClaims{
		JTI:                                 "foo-id",
		Subject:                             "peter",
		IssuedAt:                            time.Now().UTC().Round(time.Second),
		Issuer:                              "fosite",
		Audience:                            []string{"tests"},
		ExpiresAt:                           time.Now().UTC().Add(time.Hour).Round(time.Second),
		AuthTime:                            time.Now().UTC(),
		RequestedAt:                         time.Now().UTC(),
		AccessTokenHash:                     "foobar",
		CodeHash:                            "barfoo",
		AuthenticationContextClassReference: "acr",
		AuthenticationMethodsReferences:     []string{"amr"},
		Extra: map[string]interface{}{
			"foo": "bar",
			"baz": "bar",
		},
	}
	assert.Equal(t, map[string]interface{}{
		"jti":       idTokenClaims.JTI,
		"sub":       idTokenClaims.Subject,
		"iat":       idTokenClaims.IssuedAt.Unix(),
		"rat":       idTokenClaims.RequestedAt.Unix(),
		"iss":       idTokenClaims.Issuer,
		"aud":       "tests",
		"exp":       idTokenClaims.ExpiresAt.Unix(),
		"foo":       idTokenClaims.Extra["foo"],
		"baz":       idTokenClaims.Extra["baz"],
		"at_hash":   idTokenClaims.AccessTokenHash,
		"c_hash":    idTokenClaims.CodeHash,
		"auth_time": idTokenClaims.AuthTime.Unix(),
		"acr":       idTokenClaims.AuthenticationContextClassReference,
		"amr":       idTokenClaims.AuthenticationMethodsReferences,
	}, idTokenClaims.ToMap())

	idTokenClaims.Nonce = "foobar"
	assert.Equal(t, map[string]interface{}{
		"jti":       idTokenClaims.JTI,
		"sub":       idTokenClaims.Subject,
		"iat":       idTokenClaims.IssuedAt.Unix(),
		"rat":       idTokenClaims.RequestedAt.Unix(),
		"iss":       idTokenClaims.Issuer,
		"aud":       "tests",
		"exp":       idTokenClaims.ExpiresAt.Unix(),
		"foo":       idTokenClaims.Extra["foo"],
		"baz":       idTokenClaims.Extra["baz"],
		"at_hash":   idTokenClaims.AccessTokenHash,
		"c_hash":    idTokenClaims.CodeHash,
		"auth_time": idTokenClaims.AuthTime.Unix(),
		"acr":       idTokenClaims.AuthenticationContextClassReference,
		"amr":       idTokenClaims.AuthenticationMethodsReferences,
		"nonce":     idTokenClaims.Nonce,
	}, idTokenClaims.ToMap())
}

func TestIDTokenAudience(t *testing.T) {
	for _, tc := range []struct {
		aud  IDTokenAudience
		json string
		m    interface{}
	}{
		{IDTokenAudience{"wallet"}, `"wallet"`, "wallet"},
		{IDTokenAudience{"a", "b"}, `["a","b"]`, []string{"a", "b"}},
		{nil, `null`, []string{}},
	} {
		b, err := json.Marshal(tc.aud)
		require.NoError(t, err)
		assert.JSONEq(t, tc.json, string(b))
		assert.Equal(t, tc.m, (&IDTokenClaims{Audience: tc.aud}).ToMap()["aud"])
	}

	// Sessions stored by Hydra v2.2 hold a string, those stored by v26.2 before this change an array.
	for in, want := range map[string]IDTokenAudience{
		`{"aud":"wallet"}`:   {"wallet"},
		`{"aud":["wallet"]}`: {"wallet"},
		`{"aud":["a","b"]}`:  {"a", "b"},
		`{"aud":""}`:         nil,
		`{"aud":null}`:       nil,
	} {
		var c IDTokenClaims
		require.NoError(t, json.Unmarshal([]byte(in), &c), in)
		assert.Equal(t, want, c.Audience, in)
	}
}
