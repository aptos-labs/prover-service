# Aptos Keyless Prover Service

This repository contains the code for the Aptos Keyless Prover Service.

## Unit testing

To run unit tests, run 

```bash
source ./scripts/dev_setup.sh
```

then `cargo test`. 

## Local e2e testing guide (beside UTs)

NOTE: all the commands below assume the working directory is the repo root.

First, initialize the environment.
```bash
source ./scripts/dev_setup.sh
```

The prover now works with a default training wheel key pair (already prepared at `private_key_for_testing.txt`)
and optionally a "next" one (already prepared at `private_key_for_testing_another.txt`).

The prover now works with a default circuit (prepared by `dev_setup` at `~/.local/share/aptos-prover-service/setup_2024_05`)
and optionally a "next" one (prepared by `dev_setup` at `~/.local/share/aptos-prover-service/setup_initial`).

In terminal 0, prepare the mock on-chain data and mock a full node with a naive HTTP server.
```bash
LOCAL_VK_IN=~/.local/share/aptos-prover-service/setup_2024_05/verification_key.json ONCHAIN_VK_OUT=groth16_vk.json cargo test groth16_vk_rewriter
LOCAL_TW_VK_IN=private_key_for_testing.txt ONCHAIN_KEYLESS_CONFIG_OUT=keyless_config.json cargo test tw_vk_rewriter
python3 -m http.server 4444
```

In terminal 1, run the prover.
```bash
export ONCHAIN_GROTH16_VK_URL=http://localhost:4444/groth16_vk.json
export ONCHAIN_TW_VK_URL=http://localhost:4444/keyless_config.json
export PRIVATE_KEY_0=$(cat ./private_key_for_testing.txt) 
export PRIVATE_KEY_1=$(cat ./private_key_for_testing_another.txt)
export CONFIG_FILE="config_local_testing_new_setup_unspecified.yml" 
cargo run
```

Login to [send-it](https://send-it.aptoslabs.com/home/), find a real prover request payload as below.
1. Open browser developer tools (F12).
2. Navigate to Network Tab.
3. Select a request with name `prove`.
4. Go to its `Payload` detail page.

Save the payload as `prover_request_payload.json`.

In terminal 2, make a request to the prover and expect it to finish normally.
```bash
./scripts/make_request.sh http://localhost:8083 prover_request_payload.json
```
You should also see logs `use_new_setup=false` and `use_new_tw_keys=false` in terminal 1,
indicating the rotation has not happened yet.


If you rotate the training wheel keys and retry the request as follows,
```bash
LOCAL_TW_VK_IN=private_key_for_testing_another.txt ONCHAIN_KEYLESS_CONFIG_OUT=keyless_config.json cargo test tw_vk_rewriter
./scripts/make_request.sh http://localhost:8083 prover_request_payload.json
```
you should see logs become `use_new_setup=false` and `use_new_tw_keys=true` in terminal 1.

In a situation where a Groth16 key rotation has happened:
```bash
# go back to terminal 1 and ctrl+c to kill the currently running prover.
export CONFIG_FILE="config_local_testing_new_setup_specified.yml"
cargo run
```
and in terminal 2 retry the request:
```bash
./scripts/make_request.sh http://localhost:8083 prover_request_payload.json
```

you should see the logs become `use_new_setup=true` and `use_new_tw_keys=true` in terminal 1.
