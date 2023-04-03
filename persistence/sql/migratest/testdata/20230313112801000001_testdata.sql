INSERT INTO hydra_oauth2_authentication_session (
  id,
  nid,
  authenticated_at,
  subject,
  remember
) VALUES (
  'auth_session-0016',
  (SELECT id FROM networks LIMIT 1),
  CURRENT_TIMESTAMP,
  'subject-0016',
  true
);

INSERT INTO hydra_oauth2_flow (
  login_challenge,
  nid,
  requested_scope,
  login_verifier,
  login_csrf,
  subject,
  request_url,
  login_skip,
  client_id,
  requested_at,
  oidc_context,
  login_session_id,
  requested_at_audience,
  login_initialized_at,
  state,
  login_remember,
  login_remember_for,
  login_error,
  acr,
  login_authenticated_at,
  login_was_used,
  forced_subject_identifier,
  context,
  amr,
  consent_challenge_id,
  consent_verifier,
  consent_skip,
  consent_csrf,
  granted_scope,
  consent_remember,
  consent_remember_for,
  consent_error,
  session_access_token,
  session_id_token,
  consent_was_used,
  granted_at_audience,
  consent_handled_at,
  login_extend_session_lifespan
) VALUES (
  'challenge-0016',
  (SELECT id FROM networks LIMIT 1),
  '["requested_scope-0016_1","requested_scope-0016_2"]',
  'verifier-0016',
  'csrf-0016',
  'subject-0016',
  'http://request/0016',
  true,
  'client-21',
  CURRENT_TIMESTAMP,
  '{"display": "display-0016"}',
  'auth_session-0016',
  '["requested_audience-0016_1","requested_audience-0016_2"]',
  CURRENT_TIMESTAMP,
  128,
  true,
  15,
  '{}',
  'acr-0016',
  CURRENT_TIMESTAMP,
  true,
  'force_subject_id-0016',
  '{"context": "0016"}',
  '["amr-0016-1","amr-0016-2"]',
  'challenge-0016',
  'verifier-0016',
  true,
  'csrf-0016',
  '["granted_scope-0016_1","granted_scope-0016_2"]',
  true,
  15,
  '{}',
  '{"session_access_token-0016": "0016"}',
  '{"session_id_token-0016": "0016"}',
  true,
  '["granted_audience-0016_1","granted_audience-0016_2"]',
  CURRENT_TIMESTAMP,
  true
);