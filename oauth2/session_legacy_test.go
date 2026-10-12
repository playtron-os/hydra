package oauth2_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/fosite/token/jwt"
	"github.com/ory/hydra/v2/oauth2"
)

// Hydra v2.2 stored the ID token audience as a string. Every token it issued must still be readable, or refreshing
// one after the upgrade fails.
func TestSessionStoredByHydraV22(t *testing.T) {
	stored := `{"id_token":{"id_token_claims":{"jti":"j","iss":"https://oauth2.playtron.one","sub":"s","aud":"wallet",
		"exp":"2026-10-12T22:50:25Z","iat":"2026-10-12T21:50:25Z","rat":"2026-10-12T21:50:24Z","auth_time":"2026-10-12T21:50:24Z",
		"acr":"0","amr":["password","code"],"ext":{"sid":"x"}},"headers":{"extra":{"kid":"k"}},
		"expires_at":{"access_token":"2026-10-12T22:50:25Z"},"username":"","subject":"s"},
		"extra":{},"kid":"k","client_id":"wallet","consent_challenge":"c","exclude_not_before_claim":false,
		"allowed_top_level_claims":[],"mirror_top_level_claims":false}`

	var s oauth2.Session
	require.NoError(t, json.Unmarshal([]byte(stored), &s))
	assert.Equal(t, jwt.IDTokenAudience{"wallet"}, s.IDTokenClaims().Audience)

	// And it is stored the same way again, so Hydra v2.2 can read it after a rollback.
	out, err := json.Marshal(&s)
	require.NoError(t, err)
	var back map[string]any
	require.NoError(t, json.Unmarshal(out, &back))
	assert.Equal(t, "wallet", back["id_token"].(map[string]any)["id_token_claims"].(map[string]any)["aud"])
}
