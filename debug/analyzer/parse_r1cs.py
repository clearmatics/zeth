#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import json
import os
import re

def get_index(annotation_set, annotation):
    """
    Finds the index corresponding to `annotation`
    in the annotation set (which has the structure below)

    "variables_annotations":
        [
            { "index": INDEX, "annotation": ANNOTATION },

            ...

            { "index": INDEX, "annotation": ANNOTATION }
        ]
    """

    for i in range(len(annotation_set)):
        if annotation_set[i]["annotation"] == annotation:
            return annotation_set[i]["index"]


def get_constraints(constraints_set, annotation_index):
    """
    Returns the set of constraints in which a given wire figures
    (wire = index of a variable annotation)
    The set of constraints has the structure below:


    "constraints":
        [
            {
                "constraint_id": ID,
                "constraint_annotation": ANNOTATION
                "linear_combination": {
                    # `index:` Index of the wire/variable
                    # `value:` Scalar by which the wire value is multiplied
                    # by in the linear combination A
                    "A": [
                            { "index": "0", "value": "0x1" }
                        ],
                    "B": [
                            { "index": "530", "scalar": "0x1" },
                            { "index": "531", "scalar": "0x2" },
                            { "index": "532", "scalar": "0x4" }
                        ],
                    "C": [
                            { "index": "2", "scalar": "0x1" }
                        ]
                }
            }
        ]
    """

    # Array of ID of the constraints using the provided annotation index
    constraints_id = []
    for i in range(len(constraints_set)):
        lin_com_a = constraints_set[i]["linear_combination"]["A"]
        lin_com_b = constraints_set[i]["linear_combination"]["B"]
        lin_com_c = constraints_set[i]["linear_combination"]["C"]
        found_in_a = is_in_lin_comb(lin_com_a, annotation_index)
        found_in_b = is_in_lin_comb(lin_com_b, annotation_index)
        found_in_c = is_in_lin_comb(lin_com_c, annotation_index)
        if found_in_a or found_in_b or found_in_c:
            constraints_id.append(constraints_set[i]["constraint_id"])
            print("Constraint: ", str(constraints_set[i]))
    return constraints_id

def get_constraints_from_annotation_pattern(constraints_set, annotation_pattern):
    """
    Returns a set of constraints which annotation matches the given pattern.
    The regex is given by the user (which can be quite dangerous but
    the goal of this script is not to be robust anyway)
    """

    # Array of ID of the constraints using the provided annotation index
    constraints_id = []
    for i in range(len(constraints_set)):
        constraint_annotation = constraints_set[i]["constraint_annotation"]
        x = re.search(annotation_pattern, constraint_annotation)
        # If there has been a match
        if x is not None:
            constraints_id.append(constraints_set[i]["constraint_id"])
            print("Constraint: ", str(constraints_set[i]))
    return constraints_id


def is_in_lin_comb(linear_combination, annotation_index):
    """
    Inspects all the elements of the linear combination and returns
    true is the variable corresponding to the annotation_index
    is used in the linear combination
    """

    # Inspect all the linear terms
    for i in range(len(linear_combination)):
        if linear_combination[i]["index"] == annotation_index:
            return True


if __name__ == "__main__":
    path_zeth = os.environ["ZETH_DEBUG_DIR"]
    filename = "r1cs.json"

    # Read file
    file_path = os.path.join(path_zeth, filename)
    with open(file_path, 'r') as r1cs_file:
        data=r1cs_file.read()

    # Parse file
    r1cs_obj = json.loads(data)
    r1cs_variables_nb = r1cs_obj["num_variables"]
    r1cs_constraints_nb = r1cs_obj["num_constraints"]

    print("R1CS successfully loaded, vars: {}, constraints: {}"
            .format(r1cs_variables_nb, r1cs_variables_nb))

    variables_annotations_set = r1cs_obj["variables_annotations"]
    constraints_set = r1cs_obj["constraints"]

    # Some basic happy path tests are written below to try some of the
    # functions defined above
    #
    # Eg: Check the 31th bit of phi
    annotation_to_check = "joinsplit_gadget phi bits_31"
    annotation_index = get_index(variables_annotations_set, annotation_to_check)
    print("Index of the annotation to check: {}".format(annotation_index))

    print("Fetching constraints using annotation: {} of index: {}..."
            .format(annotation_to_check, annotation_index))
    constraints_using_annotation = get_constraints(constraints_set, annotation_index)
    print("Result: {}".format(constraints_using_annotation))

    regex = "rho"
    print("Testing the regex matching. Query: {}".format(regex))
    res = get_constraints_from_annotation_pattern(constraints_set, regex)
    #print(f"Result: {res}")
