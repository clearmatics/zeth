# Zeth tests

## Run the tests

```bash
# Configure your environment by running the following command from the ${ZETH} repo
cd ${ZETH}
. ./setup_env.sh

# Go in the build repository and run the following commands
cd ${ZETH}/build
cmake ..
make check # (or just "make test" if the tests are already built)

# Note: Every test can be ran independently by running the executable.
# Example:
test_prover
```
