FROM docker.io/library/ubuntu:22.04

ARG PROFILE=release

RUN apt update -y \
  && apt install -y ca-certificates libssl-dev tzdata

WORKDIR /city-rollup

COPY . /city-rollup
COPY ./target/${PROFILE}/city-rollup-cli /city-rollup

RUN echo '#!/bin/bash\n/city-rollup/city-rollup-cli $@' > /city-rollup/.entrypoint.sh
RUN chmod u+x /city-rollup/.entrypoint.sh

ENTRYPOINT ["/city-rollup/.entrypoint.sh"]
