# Circuit/R1CS analyzer

Basic set of functionalities to parse and run basic queries on the r1cs exported in a json file.

## JSON format expected for the R1CS

```json
{
    "scalar_field_characteristic": "Not yet supported. Should be bigint in hexadecimal",
    "num_variables": 549746, # Number of wires
    "num_constraints": 433391, # Number of gates
    "num_inputs": 17, # Number of primary inputs
    "variables_annotations": [ # The wires annotations
        {"index":0,"annotation":"ONE"},
        {"index":1,"annotation":"joinsplit_gadget merkle_root"},
        {"index":2,"annotation":"joinsplit_gadget in_nullifier[0]_0"},
        {"index":3,"annotation":"joinsplit_gadget in_nullifier[0]_1"},
        {"index":4,"annotation":"joinsplit_gadget in_nullifier[1]_0"},
        ...
    ],
    "constraints": [ # The gates
        {
            "constraint_id": 0,
            "constraint_annotation": "joinsplit_gadget packer_nullifiers[0] packers_0 packing_constraint",
            "linear_combination": [
                {
                "A": [
                    {
                        "index": 0, # index of the wire
                        "scalar": "0x1" # scalar used on the wire in the lin. comb
                    }
                ],
                "B": [
                    {
                        "index": 530,
                        "scalar": "0x1"
                    },
                    {
                        "index": 531,
                        "scalar": "0x2"
                    }
                ],
                "C": [
                    {
                        "index": 2,
                        "scalar": "0x1"
                    }
                ]
                }
            ]
        },
        ...
        ]
}
```
