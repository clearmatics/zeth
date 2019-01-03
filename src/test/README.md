# Zeth tests

## Run the tests

```bash
# Configure your environment by running the following command from the /zeth repo
. ./setup_env.sh

# Go in the build repository and run the following commands
cmake ..
make test_prover

# Note: All the test that are not directly related to zeth might fail!
# If you want to see the logs of the prover tests, then run (still from the build directory)
./src/test_prover
```
