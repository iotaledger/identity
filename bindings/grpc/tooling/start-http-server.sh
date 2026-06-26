#!/bin/sh
http-server ./domain-linkage-test-server &
# replace or omint the --domain parameter if you don't have a static domain or don't want to use it
ngrok http --domain=example-static-domain.ngrok-free.app 8080