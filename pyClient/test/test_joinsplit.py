from zeth.joinsplit import compute_commitment
from api.util_pb2 import ZethNote
from unittest import TestCase


class TestJoinsplit(TestCase):

    def test_compute_commitment(self) -> None:
        """
        Test the commitment value for a note, as computed by the circuit.
        """
        apk = "44810c8d62784f5e9ce862925ebb889d1076a453677a5d73567387cd5717a402"
        value = "0000000005f5e100"
        rho = "0b0bb358233326ce4d346d86f9a0c3778ed8ce15efbf7640aad6e9359145659f"
        trap_r = \
            "1e3063320fd43f2d6c456d7f1ee11b7ab486308133e2a5afe916daa4ff5357f6" + \
            "b4c262c9732b6d4d6d10f493a5e77f8c"
        cm_expect = \
            "9b8c1cb39ae9da05b9be0d8538ca6ad83181ecbfad95105dd584200414122026"

        note = ZethNote(apk=apk, value=value, rho=rho, trap_r=trap_r)
        cm = compute_commitment(note)

        self.assertEqual(cm_expect, cm.hex())
