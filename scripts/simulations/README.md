# Zeth simulation scripts

This folder contains various bash scripts and python utilities to run Zeth-related simulations.

For now, only a few agent strategies are supported (for now):
- [Singleton Deterministic Agent](./singleton_deterministic_agent.sh): Agent that operates on a fresh Zeth state, and which emits a fixed number of Zeth transactions to "self" (did not discover any other Zeth user). There is no latency between transactions. The number of emitted transactions is passed as a parameter to the script (to randomize runs, use `$((1 + $RANDOM % 1000))` to randomly determine the number of transactions the agent must emit).
- `(basic) Simulation Agent`: Agent that operates on a given state, and which emits a fixed number of Zeth transactions. There is **no** random delay/latency between each transactions. The number of emitted transactions is passed as a parameter to the script (to randomize runs, use `$((1 + $RANDOM % 1000))` to randomly determine the number of transactions the agent must emit). The agent randomly selects a recipient (from the provided config/keystore) for each transaction it fires.

## Simulations

- Each new simulation contains an initialization step that sets the initial state of the system (the state can be initialized with default/zero values for a new simulation or set to a given state to simulate on top of an existing system)
- Once the system is initialized, the initial state of the system (users' Zeth public addresses, blockchain network config, Mixer instance file etc) are passed to each agent process
- Each agent process is containerized in a docker container that interacts with the blockchain
- All agents are started via a `docker-compose` command

**WARNING:** Running a simulation with multiple agents on a single machine/laptop is very computationally expensive as it may require to instantiate multiple `prover_servers` (else, agents must be enforced to act *sequentially* to use the same `prover_server` endpoint). Hence, consider running the following simulation scripts on very performant hardware and/or consider running the [Singleton Deterministic Agent](./singleton_deterministic_agent.sh) which allows to generate and fire a set of Zeth transactions on a new Zeth deployment.