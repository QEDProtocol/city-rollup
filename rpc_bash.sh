#!/bin/bash
BASH_FILE_ME=${BASH_SOURCE[0]}
CITY_RPC_URL="http://localhost:3000"

sub_user_ids() {
  PUBLIC_KEY=${1:-0000}

  RPC_RESULT=$(curl -s http://localhost:3000 -X POST -H "Content-Type: application/json" --data "{\"method\":\"cr_getUserIdsForPublicKey\",\"params\":[\"${PUBLIC_KEY}\"],\"id\":1,\"jsonrpc\":\"2.0\"}")
  echo "$RPC_RESULT" | jq '.result'
}
sub_user_id() {
  PUBLIC_KEY=${1:-0000}

  RPC_RESULT=$(curl -s http://localhost:3000 -X POST -H "Content-Type: application/json" --data "{\"method\":\"cr_getUserIdsForPublicKey\",\"params\":[\"${PUBLIC_KEY}\"],\"id\":1,\"jsonrpc\":\"2.0\"}")
  echo "$RPC_RESULT" | jq '.result[0]'
}



sub_help() {
  echo "City Rollup RPC Script"
}

subcommand=$1
case $subcommand in
    "" | "-h" | "--help")
        sub_help
        ;;
    *)
        shift
        sub_${subcommand} $@
        if [ $? = 127 ]; then
            echo "Error: '$subcommand' is not a known subcommand." >&2
            echo "       Run '$ProgName --help' for a list of known subcommands." >&2
            exit 1
        fi
        ;;
esac