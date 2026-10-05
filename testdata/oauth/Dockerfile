# Postgres 18 with a test OAuth validator, so the compatibility suite can log in with OAUTHBEARER through QueryGuard.
FROM postgres:18
COPY validator.c /tmp/validator.c
RUN apt-get update \
	&& apt-get install -y --no-install-recommends gcc libc6-dev postgresql-server-dev-18 \
	&& gcc -shared -fPIC -O2 -I"$(pg_config --includedir-server)" -o "$(pg_config --pkglibdir)/qg_oauth.so" /tmp/validator.c \
	&& apt-get purge -y gcc libc6-dev postgresql-server-dev-18 && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* /tmp/validator.c
