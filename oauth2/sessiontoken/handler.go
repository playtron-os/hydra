package sessiontoken

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/herodot"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/httprouterx"
)

const IssueTokenPath = "/sessions/token"

type Handler struct {
	r InternalRegistry
}

func NewHandler(r InternalRegistry) *Handler {
	return &Handler{r: r}
}

func (h *Handler) SetRoutes(r *httprouterx.RouterAdmin) {
	r.POST(IssueTokenPath, h.issueToken)
}

type IssueTokenRequest struct {
	Subject   string         `json:"subject"`
	ClientID  string         `json:"client_id"`
	Extra     map[string]any `json:"extra"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"` // optional ISO timestamp
}

type IssueTokenResponse struct {
	Token string `json:"token"`
}

func (h *Handler) issueToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()

	var req IssueTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}
	if req.Subject == "" || req.ClientID == "" {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(herodot.ErrBadRequest.WithReason("subject and client_id are required")))
		return
	}

	_, err := h.r.ClientManager().GetClient(ctx, req.ClientID)
	if err != nil {
		if errorsx.Cause(err).Error() == "not found" {
			h.r.Writer().WriteError(w, r, errorsx.WithStack(herodot.ErrNotFound.WithReason("client_id not found")))
			return
		}
		h.r.Writer().WriteError(w, r, errorsx.WithStack(herodot.ErrInternalServerError.WithWrap(err)))
		return
	}

	exp := time.Now().Add(time.Hour)
	if req.ExpiresAt != nil {
		exp = *req.ExpiresAt
	}

	keySet, err := h.r.KeyManager().GetKeySet(ctx, "hydra.jwt.access-token")
	if err != nil || len(keySet.Keys) == 0 {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(herodot.ErrInternalServerError.WithWrap(err)))
		return
	}

	signer := &jwt.DefaultSigner{
		GetPrivateKey: func(ctx context.Context) (any, error) {
			return keySet.Keys[0].Key, nil
		},
	}

	// Reserved claims that should not be overwritten by user input
	reserved := map[string]struct{}{
		"iss": {}, "sub": {}, "aud": {}, "exp": {}, "iat": {}, "jti": {},
	}

	claims := jwt.MapClaims{
		"iss": h.r.Config().IssuerURL(r.Context()).String(),
		"sub": req.Subject,
		"aud": req.ClientID,
		"exp": exp.Unix(),
		"iat": time.Now().Unix(),
		"jti": uuid.NewString(),
	}

	// Merge in safe custom claims
	for k, v := range req.Extra {
		if _, exists := reserved[k]; !exists {
			claims[k] = v
		}
	}

	// If nonce is not set, generate a default one
	if _, ok := claims["nonce"]; !ok {
		claims["nonce"] = uuid.NewString()
	}

	header := &jwt.Headers{
		Extra: map[string]any{
			"kid": keySet.Keys[0].KeyID,
		},
	}

	token, _, err := signer.Generate(ctx, claims, header)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().Write(w, r, IssueTokenResponse{Token: token})
}
