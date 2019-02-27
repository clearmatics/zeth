const crypto = require('crypto');

const MerkleTreeSha256 = artifacts.require("./MerkleTreeSha256.sol");

function prefixHexadecimalString(hex_str) {
  return "0x" + hex_str;
}

contract('MerkleTreeSha256', (accounts) => {
  it('Test default value of merkle tree', async () => {
    // We have a merkle tree of depth 3 for the tests
    let instance = await MerkleTreeSha256.deployed();

    // --- Expected values --- //
    // All the nodes at index [7, 8, 9, 10, 11, 12, 13, 14] have the zero value
    let expectedValueNodeLayer3 = Buffer.from(new Uint8Array(32)).toString('hex');
    // All the nodes at index [3,4,5,6] have the same value (= sha256(initialValueLeftNodeLayer3 + initialValueRightNodeLayer3))
    let expectedValueNodeLayer2 = crypto.createHash('sha256').
      update(Buffer.from(expectedValueNodeLayer3 + expectedValueNodeLayer3, 'hex')).
      digest('hex');
    // All the nodes at index [1,2] have the same value (= sha256(initialValueLeftNodeLayer2 + initialValueRightNodeLayer2))
    let expectedValueNodeLayer1 = crypto.createHash('sha256').
      update(Buffer.from(expectedValueNodeLayer2 + expectedValueNodeLayer2, 'hex')).
      digest('hex');
    // The value of the root node at index [0] (= sha256(initialValueLeftNodeLayer1 + initialValueRightNodeLayer1))
    let expectedValueNodeLayer0 = crypto.createHash('sha256').
      update(Buffer.from(expectedValueNodeLayer1 + expectedValueNodeLayer1, 'hex')).
      digest('hex');

    // --- Actual values from the smart contract --- //
    let actualInitialTree = await instance.getTree();

    // --- Asserts --- //
    for(var i = 7; i < actualInitialTree.length; i++) {
      console.log("(Layer3-Leaves) Node" + i + " => " + actualInitialTree[i]);
      assert.equal(
        prefixHexadecimalString(expectedValueNodeLayer3),
        actualInitialTree[i],
        "Mismatch between actual and expected value for node (" + i + ") of Layer3"
      );
    }
    for(var i = 3; i < 7; i++) {
      console.log("(Layer2) Node" + i + " => " + actualInitialTree[i]);
      assert.equal(
        prefixHexadecimalString(expectedValueNodeLayer2),
        actualInitialTree[i],
        "Mismatch between actual and expected value for node (" + i + ") of Layer2"
      );
    }
    for(var i = 1; i < 3; i++) {
      console.log("(Layer1) Node" + i + " => " + actualInitialTree[i]);
      assert.equal(
        prefixHexadecimalString(expectedValueNodeLayer1),
        actualInitialTree[i],
        "Mismatch between actual and expected value for node (" + i + ") of Layer1"
      );
    }
    console.log("(Layer0-Root) Node 0 => " + actualInitialTree[0]);
    assert.equal(
      prefixHexadecimalString(expectedValueNodeLayer0),
      actualInitialTree[0],
      "Mismatch between actual and expected value for node (0) of Layer0-Root"
    );
  });

  it('Test insertion in the merkle tree', async () => {
    // We have a merkle tree of depth 3 for the tests
    let instance = await MerkleTreeSha256.deployed();

    // --- Leaves layer (layer 3) --- //
    // We insert at the first available leaf (leftmost leaf --> index 7 in the tree of depth 3)
    var expectedValueNode7 = crypto.createHash('sha256').update("test-commitment").digest('hex')
    // All the nodes at index [8, 9, 10, 11, 12, 13, 14] have the zero value
    let expectedValueOtherNodesLayer3 = Buffer.from(new Uint8Array(32)).toString('hex');

    // --- Layer 2 --- //
    // The value of node3
    let expectedValueNode3 = crypto.createHash('sha256').
      update(Buffer.from(expectedValueNode7 + expectedValueOtherNodesLayer3, 'hex')).
      digest('hex');
    // All the nodes at index [4,5,6] have the same value (= sha256(initialValueLeftNodeLayer3 || initialValueRightNodeLayer3))
    let expectedValueOtherNodesLayer2 = crypto.createHash('sha256').
      update(Buffer.from(expectedValueOtherNodesLayer3 + expectedValueOtherNodesLayer3, 'hex')).
      digest('hex');

    // --- Layer 1 --- //
    // The value of node 1
    let expectedValueNode1 = crypto.createHash('sha256').
      update(Buffer.from(expectedValueNode3 + expectedValueOtherNodesLayer2, 'hex')).
      digest('hex');
    // The value of node 2
    let expectedValueNode2 = crypto.createHash('sha256').
      update(Buffer.from(expectedValueOtherNodesLayer2 + expectedValueOtherNodesLayer2, 'hex')).
      digest('hex');

    // --- Layer 0 - Root --- //
    // The value of the root node at index [0] (= sha256(value node 1(Left) || value node 2(Right)))
    let expectedValueNodeLayer0 = crypto.createHash('sha256').
      update(Buffer.from(expectedValueNode1 + expectedValueNode2, 'hex')).
      digest('hex');

    // --- Insertion of the commitment at the left most free leaf (Leaf 7 here) --- //
    let addressInsertion = await instance.insert("0x" + expectedValueNode7);

    // --- Assert to verify that the new merkle tree has the expected values --- //
    let actualInitialTree = await instance.getTree();
    console.log("(Layer3-Location of insertion) Node7 => " + actualInitialTree[7]);
    assert.equal(
      prefixHexadecimalString(expectedValueNode7), actualInitialTree[7],
      "Mismatch between actual and expected value for node (7) of Layer3"
    );
    for(var i = 8; i < actualInitialTree.length; i++) {
      console.log("(Layer3-Leaves) Node" + i + " => " + actualInitialTree[i]);
      assert.equal(
        prefixHexadecimalString(expectedValueOtherNodesLayer3), actualInitialTree[i],
        "Mismatch between actual and expected value for node (" + i + ") of Layer3"
      );
    }

    console.log("(Layer2-Parent of inserted commitment) Node3 => " + actualInitialTree[3]);
    assert.equal(
      prefixHexadecimalString(expectedValueNode3), actualInitialTree[3],
      "Mismatch between actual and expected value for node (3) of Layer2"
    );
    for(var i = 4; i < 7; i++) {
      console.log("(Layer2) Node" + i + " => " + actualInitialTree[i]);
      assert.equal(
        prefixHexadecimalString(expectedValueOtherNodesLayer2), actualInitialTree[i],
        "Mismatch between actual and expected value for node (" + i + ") of Layer2"
      );
    }

    console.log("(Layer1-Grand Parent of inserted commitment) Node1 => " + actualInitialTree[1]);
    assert.equal(
      prefixHexadecimalString(expectedValueNode1), actualInitialTree[1],
      "Mismatch between actual and expected value for node (1) of Layer1"
    );
    console.log("(Layer1) Node 2 => " + actualInitialTree[2]);
    assert.equal(
      prefixHexadecimalString(expectedValueNode2), actualInitialTree[2],
      "Mismatch between actual and expected value for node (2) of Layer1"
    );

    console.log("(Layer0-Root) Node 0 => " + actualInitialTree[0]);
    assert.equal(
      prefixHexadecimalString(expectedValueNodeLayer0), actualInitialTree[0],
      "Mismatch between actual and expected value for node (0) of Layer0-Root"
    );
  });
});
