# Identity.rs gRPC Bindings
This project provides the functionalities of [Identity.rs](https://github.com/iotaledger/identity.rs) in a language-agnostic way through a [gRPC](https://grpc.io) server.

The server can easily be run with docker using [this dockerfile](https://github.com/iotaledger/identity.rs/blob/grpc-bindings/bindings/grpc/Dockerfile).

## Build
Run `docker build -f bindings/grpc/Dockerfile -t iotaleger/identity-grpc .` from the project root.

### Dockerimage env variables and volume binds
The provided docker image requires the following variables to be set in order to properly work:
- `API_ENDPOINT`: IOTA's node address.
- `STRONGHOLD_PWD`: Stronghold password.
- `SNAPSHOT_PATH`: Stronghold's snapshot location.

Make sure to provide a valid stronghold snapshot at the provided `SNAPSHOT_PATH` prefilled with all the needed key material.

### Available services
| Service description                                                            | Service Id                                                               | Proto File                                                                                                                    |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| Credential Revocation Checking                                                 | `credentials/CredentialRevocation.check`                                 | [credentials.proto](https://github.com/iotaledger/identity.rs/blob/grpc-bindings/bindings/grpc/proto/credentials.proto)       |
| SD-JWT Validation                                                              | `sd_jwt/Verification.verify`                                             | [sd_jwt.proto](https://github.com/iotaledger/identity.rs/blob/grpc-bindings/bindings/grpc/proto/sd_jwt.proto)                 |
| Credential JWT creation                                                        | `credentials/Jwt.create`                                                 | [credentials.proto](https://github.com/iotaledger/identity.rs/blob/grpc-bindings/bindings/grpc/proto/credentials.proto)       |
| Credential JWT validation                                                      | `credentials/VcValidation.validate`                                      | [credentials.proto](https://github.com/iotaledger/identity.rs/blob/grpc-bindings/bindings/grpc/proto/credentials.proto)       |
| DID Document Creation                                                          | `document/DocumentService.create`                                        | [document.proto](https://github.com/iotaledger/identity.rs/blob/grpc-bindings/bindings/grpc/proto/document.proto)             |
| Domain Linkage - validate domain, let server fetch did-configuration           | `domain_linkage/DomainLinkage.validate_domain`                           | [domain_linkage.proto](https://github.com/iotaledger/identity.rs/blob/grpc-bindings/bindings/grpc/proto/domain_linkage.proto) |
| Domain Linkage - validate domain, pass did-configuration to service            | `domain_linkage/DomainLinkage.validate_domain_against_did_configuration` | [domain_linkage.proto](https://github.com/iotaledger/identity.rs/blob/grpc-bindings/bindings/grpc/proto/domain_linkage.proto) |
| Domain Linkage - validate endpoints in DID, let server fetch did-configuration | `domain_linkage/DomainLinkage.validate_did`                              | [domain_linkage.proto](https://github.com/iotaledger/identity.rs/blob/grpc-bindings/bindings/grpc/proto/domain_linkage.proto) |
| Domain Linkage - validate endpoints in DID, pass did-configuration to service  | `domain_linkage/DomainLinkage.validate_did_against_did_configurations`   | [domain_linkage.proto](https://github.com/iotaledger/identity.rs/blob/grpc-bindings/bindings/grpc/proto/domain_linkage.proto) |

## Testing
### Domain Linkage
Following is a description about how to manually test the domain linkage service. The steps for the other services might vary a bit.

#### Http server
If you want to test domain linkage, you need a server, that's reachable via HTTPS. If you already have one, ignore the server setup steps here and just make sure your server provides the `did-configuration.json` file as described here.

- create test server folder with did configuration in it, e.g. (you can also use the template in `./tooling/domain-linkage-test-server`)
    ```raw
    test-server/
    └── .well-known
        └── did-configuration.json
    ```
    
    `did-configuration` looks like this for now:  
    
    ```json
    {
        "@context": "https://identity.foundation/.well-known/did-configuration/v1",
        "linked_dids": [
            "add your domain linkage credential here"
        ]
    }
    ```
- start a server, that will serve this folder, e.g. with a "http-server" from NodeJs : `http-server  ./test-server/`, in this example the server should now be running on local port 8080
- now tunnel your server's port (here 8080) to a public domain with https, e.g. with ngrok:
    `ngrok http http://127.0.0.1:8080`  
    the output should now have a line like  
    `Forwarding                    https://0d40-2003-d3-2710-e200-485f-e8bb-7431-79a7.ngrok-free.app -> http://127.0.0.1:8080`  
    check that the https url is reachable, this will be used in the next step. you can also start ngrok with a static domain, that you do not have to update credentials after each http server restart
- for convenience, you can find a script to start the HTTP server, that you can adjust in `tooling/start-http-server.sh`, don't forget to insert your static domain or to remove the `--domain` parameter

#### Domain linkage credential
- copy this public url and insert it into the advanced test 6 (the one for domain linkage) as domain 1, e.g. `let domain_1: Url = Url::parse("https://0d40-2003-d3-2710-e200-485f-e8bb-7431-79a7.ngrok-free.app")?;`
- run the example with `cargo run --release --example 6_domain_linkage`

#### GRPC server
- grab the configuration resource from the log and replace the contents of your `did-configuration.json` with it
- you now have a publicly reachable (sub)domain, that serves a `did-configuration` file containing a credential pointing to your DID
- to verify this, run the server via Docker or with the following command, remember to replace the placeholders ;) `API_ENDPOINT=replace_me STRONGHOLD_PWD=replace_me SNAPSHOT_PATH=replace_me cargo run --release`, arguments can be taken from examples, e.g. after running a `6_domain_linkage.rs`, that also logs snapshot path passed to secret manager (`let snapshot_path = random_stronghold_path(); dbg!(&snapshot_path.to_str());`), for example
    - API_ENDPOINT: `"http://localhost"`
    - STRONGHOLD_PWD: `"secure_password"`
    - SNAPSHOT_PATH: `"/var/folders/41/s1sm86jx0xl4x435t81j81440000gn/T/test_strongholds/8o2Nyiv5ENBi7Ik3dEDq9gNzSrqeUdqi.stronghold"`
- for convenience, you can find a script to start the GRPC server, that you can adjust in `tooling/start-rpc-server.sh`, don't forget to insert the env variables as described above

#### Calling the endpoints
- call the `validate_domain` endpoint with your domain, e.g with:
    
    ```json
    {
        "domain": "https://0d40-2003-d3-2710-e200-485f-e8bb-7431-79a7.ngrok-free.app"
    }
    ```
    
    you should now receive a response like this:  
    
    ```json
    {
        "linked_dids": [
            {
                "document": "... (compact JWT domain linkage credential)",
                "status": "ok"
            }
        ]
    }
    ```

- to call the `validate_did` endpoint, you need a DID to check, you can find a testable in you domain linkage credential. for this just decode it (e.g. on jwt.io) and get the `iss` value, then you can submit as "did" like following

    ```json
    {
        "did": "did:iota:snd:0x967bf8f0c7487f61378611b6a1c6a59cb99e65b839681ee70be691b09a024ab9"
    }
    ```

    you should not receive a response like this:

    ```json
    {
        "service": [
            {
                "service_endpoint": [
                    {
                        "valid": true,
                        "document": "eyJraWQiOiJkaWQ6aW90YTpzbmQ6MHg5NjdiZjhmMGM3NDg3ZjYxMzc4NjExYjZhMWM2YTU5Y2I5OWU2NWI4Mzk2ODFlZTcwYmU2OTFiMDlhMDI0YWI5IzA3QjVWRkxBa0FabkRhaC1OTnYwYUN3TzJ5ZnRzX09ZZ0YzNFNudUloMlUiLCJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJleHAiOjE3NDE2NzgyNzUsImlzcyI6ImRpZDppb3RhOnNuZDoweDk2N2JmOGYwYzc0ODdmNjEzNzg2MTFiNmExYzZhNTljYjk5ZTY1YjgzOTY4MWVlNzBiZTY5MWIwOWEwMjRhYjkiLCJuYmYiOjE3MTAxNDIyNzUsInN1YiI6ImRpZDppb3RhOnNuZDoweDk2N2JmOGYwYzc0ODdmNjEzNzg2MTFiNmExYzZhNTljYjk5ZTY1YjgzOTY4MWVlNzBiZTY5MWIwOWEwMjRhYjkiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaWRlbnRpdHkuZm91bmRhdGlvbi8ud2VsbC1rbm93bi9kaWQtY29uZmlndXJhdGlvbi92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsib3JpZ2luIjoiaHR0cHM6Ly9ob3QtYnVsbGRvZy1wcm9mb3VuZC5uZ3Jvay1mcmVlLmFwcC8ifX19.69e7T0DbRw9Kz7eEQ96P9E5HWbEo5F1fLuMjyQN6_Oa1lwBdbfj0wLlhS1j_d8AuNmvu60lMdLVixjMZJLQ5AA"
                    },
                    {
                        "valid": false,
                        "error": "domain linkage error: error sending request for url (https://bar.example.com/.well-known/did-configuration.json): error trying to connect: dns error: failed to lookup address information: nodename nor servname provided, or not known"
                    }
                ],
                "id": "did:iota:snd:0x967bf8f0c7487f61378611b6a1c6a59cb99e65b839681ee70be691b09a024ab9"
            }
        ]
    }
    ```

    Which tells us that it found a DID document with one matching service with a serviceEndpoint, that contains two domains. Out of these domains one links back to the given DID, the other domain could not be resolved.
