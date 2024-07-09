#!/bin/bash
set -e

SSH_PROXY="$(mktemp)"
go build -o "$SSH_PROXY" ..
"$SSH_PROXY" --config ./ssh-proxy-test.yaml &
SERVER_PID="$!"
trap "kill $SERVER_PID; rm $SSH_PROXY" EXIT
sleep 3

function ssh {
    exec /bin/ssh -p 4322 -o StrictHostKeyChecking=accept-new "$@"
}

function check {
    if [ "$(curl -sI localhost:8080 | head -c 8)" == "HTTP/1.1" ]
        then return 0
        else return 1
    fi
}

function check-no-access {
    if check
        then return 1
        else return 0
    fi
}

# example user can access 1.1.1.1
ssh -i ./id_ed25519 -NL 8080:1.1.1.1:80 example@localhost &
sleep 1
check
kill -KILL $!
sleep 1

# example user cannot access 1.0.0.1
ssh -i ./id_ed25519 -NL 8080:1.0.0.1:80 example@localhost &
sleep 1
check-no-access
kill $!
sleep 1

# foo user can access 1.1.1.1
ssh -i ./id_rsa -NL 8080:1.1.1.1:80 foo@localhost &
sleep 1
check
kill $!
sleep 1

# foo user can access 1.0.0.1
ssh -i ./id_rsa -NL 8080:1.0.0.1:80 foo@localhost &
sleep 1
check
kill $!
sleep 1

if ssh -i ./id_ed25519 -NL 8080:1.0.0.1:80 foo@localhost; then
    echo "example key worked for user foo"
    exit 1
fi
