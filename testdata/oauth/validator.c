/* A test OAuth validator for PostgreSQL 18: it accepts one fixed bearer token, for QueryGuard's compatibility tests only. */
#include "postgres.h"

#include "fmgr.h"
#include "libpq/oauth.h"

PG_MODULE_MAGIC;

static bool
validate(const ValidatorModuleState *state, const char *token, const char *role, ValidatorModuleResult *result)
{
	result->authorized = strcmp(token, "queryguard-test-token") == 0;
	result->authn_id = result->authorized ? pstrdup(role) : NULL;
	return true;
}

static const OAuthValidatorCallbacks callbacks = {
	.magic = PG_OAUTH_VALIDATOR_MAGIC,
	.validate_cb = validate,
};

const OAuthValidatorCallbacks *
_PG_oauth_validator_module_init(void)
{
	return &callbacks;
}
