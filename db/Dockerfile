FROM postgres:16

ARG REPLUSER
ARG REPLPASSWORD
ARG DATABASE

COPY init.sql /init.sql


RUN sed -i 's/telegram_bot/'"$DATABASE"'/g' /init.sql

RUN sed -i 's/repl_user/'"$REPLUSER"'/g' /init.sql

RUN sed -i 's/Qq12345/'"$REPLPASSWORD"'/g' /init.sql



RUN mv init.sql /docker-entrypoint-initdb.d/




CMD ["postgres"]
