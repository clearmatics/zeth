# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.pairing import PairingParameters, G1Point, G2Point, \
    g1_point_negate, g2_point_negate
from unittest import TestCase


# pylint: disable=line-too-long
ALT_BN128_PAIRING = PairingParameters.from_json_dict({
    "r": "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
    "q": "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
    "generator_g1": [
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000002"
    ],
    "generator_g2": [
        ["0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
         "0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"],
        ["0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
         "0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"],
    ]
})

ALT_BN128_G1_MINUS_1 = G1Point.from_json_list([
    "0x0000000000000000000000000000000000000000000000000000000000000001",
    "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"])

ALT_BN128_G1_8 = G1Point.from_json_list([
    "0x08b1d51d23480c10f472f5e93b9cfea88238c121fe155af7043937882c306a63",
    "0x299836713dad3fa34e337aa412466015c366af8ec50b9d7bd05aa74642822021"])

ALT_BN128_G1_MINUS_8 = G1Point.from_json_list([
    "0x08b1d51d23480c10f472f5e93b9cfea88238c121fe155af7043937882c306a63",
    "0x06cc1801a38460866a1ccb126f3af847d41abb02a3662d116bc5e4d095fadd26"])

ALT_BN128_G2_MINUS_1 = G2Point.from_json_list([
    ["0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
     "0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"],
    ["0x275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec",
     "0x1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d"]])

ALT_BN128_G2_8 = G2Point.from_json_list([
    ["0x03589520df85791604b5a2b720a21139aabdb41949d47779484b0db588bfa699",
     "0x18afc7fd8df1c902383c213b6d989f0066b7eca1388be49721792278984d9a29"],
    ["0x2cc25982f4a3b75f57f8f3e966d75e6da8c51776bf0828c7ce3f10171793cd2a",
     "0x17623e9e90176bcdf8454daa96008240b12709ca5d79de805744cfd137609bec"]])

ALT_BN128_G2_MINUS_8 = G2Point.from_json_list([
    ["0x03589520df85791604b5a2b720a21139aabdb41949d47779484b0db588bfa699",
     "0x18afc7fd8df1c902383c213b6d989f0066b7eca1388be49721792278984d9a29"],
    ["0x03a1f4efec8de8ca605751cd1aa9f9efeebc531aa969a1c56de17bffc0e9301d",
     "0x19020fd4511a345bc00af80beb80d61ce65a60c70af7ec0ce4dbbc45a11c615b"]])


BW6_761_PAIRING = PairingParameters.from_json_dict({
    "r": "0x01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001",  # noqa
    "q": "0x0122e824fb83ce0ad187c94004faff3eb926186a81d14688528275ef8087be41707ba638e584e91903cebaff25b423048689c8ed12f9fd9071dcd3dc73ebff2e98a116c25667a8f8160cf8aeeaf0a437e6913e6870000082f49d00000000008b",  # noqa
    "generator_g1": [
        "0x01075b020ea190c8b277ce98a477beaee6a0cfb7551b27f0ee05c54b85f56fc779017ffac15520ac11dbfcd294c2e746a17a54ce47729b905bd71fa0c9ea097103758f9a280ca27f6750dd0356133e82055928aca6af603f4088f3af66e5b43d",  # noqa
        "0x0058b84e0a6fc574e6fd637b45cc2a420f952589884c9ec61a7348d2a2e573a3265909f1af7e0dbac5b8fa1771b5b806cc685d31717a4c55be3fb90b6fc2cdd49f9df141b3053253b2b08119cad0fb93ad1cb2be0b20d2a1bafc8f2db4e95363"  # noqa
    ],
    "generator_g2": [
        "0x0110133241d9b816c852a82e69d660f9d61053aac5a7115f4c06201013890f6d26b41c5dab3da268734ec3f1f09feb58c5bbcae9ac70e7c7963317a300e1b6bace6948cb3cd208d700e96efbc2ad54b06410cf4fe1bf995ba830c194cd025f1c",  # noqa
        "0x0017c3357761369f8179eb10e4b6d2dc26b7cf9acec2181c81a78e2753ffe3160a1d86c80b95a59c94c97eb733293fef64f293dbd2c712b88906c170ffa823003ea96fcd504affc758aa2d3a3c5a02a591ec0594f9eac689eb70a16728c73b61"  # noqa
    ],
})

BW6_761_G1_MINUS_1 = G1Point.from_json_list([
    "0x01075b020ea190c8b277ce98a477beaee6a0cfb7551b27f0ee05c54b85f56fc779017ffac15520ac11dbfcd294c2e746a17a54ce47729b905bd71fa0c9ea097103758f9a280ca27f6750dd0356133e82055928aca6af603f4088f3af66e5b43d",  # noqa
    "0x00ca2fd6f1140895ea8a65c4bf2ed4fca990f2e0f984a7c2380f2d1cdda24a9e4a229c473606db5e3e15c0e7b3fe6afdba216bbba17fb13ab39d1ad104293159f9032580a36276a4635c7795201fa8a439748baa64df2de139a070d24b16ad28"])  # noqa

BW6_761_G1_8 = G1Point.from_json_list([
    "0x00c7c9438e7e51aa9360612e3cedb297517ebd7a071571b771d86f68c9ec1b280cbcccffdb49ce6e9f77adfa85aae465d0d3c60eec959a99e296042bb6522505a25a4b9ac5a5d224d1ed2c9f6644ab31d68796d3cdf6f3b8ece3f7d4b4054f45",  # noqa
    "0x0059c012c23f88eb30ff96071448886d5b90074112c2cbf6c104b61d11a39f4798f3a1395bc1c69afe7cc9c7f24679b856a9ce03eb716ba27f668281515b297d6fe591623818e5ed45dfb885b3885c725d5c4af7e490825fe076fd5cec097458"])  # noqa

BW6_761_G1_MINUS_8 = G1Point.from_json_list([
    "0x00c7c9438e7e51aa9360612e3cedb297517ebd7a071571b771d86f68c9ec1b280cbcccffdb49ce6e9f77adfa85aae465d0d3c60eec959a99e296042bb6522505a25a4b9ac5a5d224d1ed2c9f6644ab31d68796d3cdf6f3b8ece3f7d4b4054f45",  # noqa
    "0x00c928123944451fa0883338f0b276d15d9611296f0e7a91917dbfd26ee41ef9d78804ff89c3227e0551f137336da94c2fdffae9278891edf276515b2290d5b128bb85601e4ec30ad02d4029376847c58934f3708b6f7e23142602a313f68c33"])  # noqa

BW6_761_G2_MINUS_1 = G2Point.from_json_list([
    "0x0110133241d9b816c852a82e69d660f9d61053aac5a7115f4c06201013890f6d26b41c5dab3da268734ec3f1f09feb58c5bbcae9ac70e7c7963317a300e1b6bace6948cb3cd208d700e96efbc2ad54b06410cf4fe1bf995ba830c194cd025f1c",  # noqa
    "0x010b24ef8422976b500dde2f20442c62926e48cfb30f2e6bd0dae7c82c87db2b665e1f70d9ef437c6f053c47f28ae315219735114032ead7e8d6126b7443dc2e59f7a6f5061ca930bd62cb74ae96a19254a538d3761539f9092c5e98d738c52a"])  # noqa

BW6_761_G2_8 = G2Point.from_json_list([
    "0x0099155657cfbc579c893f9052bc8e431718c6aaf22583ff79d22b3eb30daaa31ea7def53f90c5719c38599490604cf0447c30b495723f16468a4c4cbcdcf3be3564274269ddd9e0b376d98ddd1cae3293eeeb7cfe1e0b937db9e60b56c5f6b1",  # noqa
    "0x011a9fcd05529c46d7d5c226edea31829dd897465f3a4a2773cb88179324ccff6b0d4bf3dd95bbeb000db16f27cee591f949aa6f6df17cec9a63dc660f4aa79fed5512a98239b73fdff458e7c0e09b9d246e3f5681429affc2b1f7e2fcbd1141"])  # noqa

BW6_761_G2_MINUS_8 = G2Point.from_json_list([
    "0x0099155657cfbc579c893f9052bc8e431718c6aaf22583ff79d22b3eb30daaa31ea7def53f90c5719c38599490604cf0447c30b495723f16468a4c4cbcdcf3be3564274269ddd9e0b376d98ddd1cae3293eeeb7cfe1e0b937db9e60b56c5f6b1",  # noqa
    "0x00084857f63131c3f9b207191710cdbc1b4d81242296fc60deb6edd7ed62f142056e5a4507ef2d2e03c1098ffde53d728d401e7da50880a3d778f77664a1578eab4c0418d42df1b836189fc72a10089ac222ff11eebd658331eb081d0342ef4a"])  # noqa


BLS12_377_PAIRING = PairingParameters.from_json_dict({
    "r": "0x12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000001",
    "q": "0x01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001",  # noqa
    "generator_g1": [
        "0x008848defe740a67c8fc6225bf87ff5485951e2caa9d41bb188282c8bd37cb5cd5481512ffcd394eeab9b16eb21be9ef",  # noqa
        "0x01914a69c5102eff1f674f5d30afeec4bd7fb348ca3e52d96d182ad44fb82305c2fe3d3634a9591afd82de55559c8ea6"  # noqa
    ],
    "generator_g2": [
        ["0x00d6ac33b84947d9845f81a57a136bfa326e915fabc8cd6a57ff133b42d00f62e4e1af460228cd5184deae976fa62596",  # noqa
         "0x00b997fef930828fe1b9e6a1707b8aa508a3dbfd7fe2246499c709226a0a6fef49f85b3a375363f4f8f6ea3fbd159f8a"],  # noqa
        ["0x0185067c6ca76d992f064a432bd9f9be832b0cac2d824d0518f77d39e76c3e146afb825f2092218d038867d7f337a010",  # noqa
         "0x0118dd509b2e9a13744a507d515a595dbb7e3b63df568866473790184bdf83636c94df2b7a962cb2af4337f07cb7e622"]  # noqa
    ],
})

BLS12_377_G1_MINUS_1 = G1Point.from_json_list([
    "0x008848defe740a67c8fc6225bf87ff5485951e2caa9d41bb188282c8bd37cb5cd5481512ffcd394eeab9b16eb21be9ef",  # noqa
    "0x001cefdc52b4e1eba6d3b6633bf15a765ca326aa36b6c0b5b1db375b6a5124fa540d200dfb56a6e58785e1aaaa63715b"])  # noqa

BLS12_377_G1_8 = G1Point.from_json_list([
    "0x018aff632c0048f5afb5c07fd197a44a127c829be3ff6170c6cebc1154bc72633b45de2ac855e0da30cebfa33672e7f3",  # noqa
    "0x00efb82d5f13565755df1445db9ed4c4969f09bb31cc610f83eb1490be76ab3817808c52d98074f1a98ff896012a78ab"])  # noqa

BLS12_377_G1_MINUS_8 = G1Point.from_json_list([
    "0x018aff632c0048f5afb5c07fd197a44a127c829be3ff6170c6cebc1154bc72633b45de2ac855e0da30cebfa33672e7f3",  # noqa
    "0x00be8218b8b1ba93705bf17a910274768383d037cf28b27f9b084d9efb929cc7ff8ad0f1567f8b0edb78c769fed58756"])  # noqa

BLS12_377_G2_MINUS_1 = G2Point.from_json_list([
    ["0x00d6ac33b84947d9845f81a57a136bfa326e915fabc8cd6a57ff133b42d00f62e4e1af460228cd5184deae976fa62596",  # noqa
     "0x00b997fef930828fe1b9e6a1707b8aa508a3dbfd7fe2246499c709226a0a6fef49f85b3a375363f4f8f6ea3fbd159f8a"],  # noqa
    ["0x002933c9ab1da3519734bb7d40c74f7c96f7cd46d372c68a05fbe4f5d29d09ebac0fdae50f6dde73818058280cc85ff1",  # noqa
     "0x00955cf57c9676d751f0b5431b46efdd5ea49e8f219e8b28d7bbd2176e29c49caa767e18b569d34dd5c5880f834819df"]])  # noqa

BLS12_377_G2_8 = G2Point.from_json_list([
    ["0x019ece89be3c82b561d87e7898ddfc928d2e86fafa21febc222d8ff38a752fe95b25e19b25410205800385fb047ca1cf",  # noqa
    "0x016251c985d96e59d07cc363290ec7146682da9bde87ed3d64ccad05403992cc9f3704c7f9a1df34116840d220edba27"],  # noqa
    ["0x012c74d25dd0ca3264d6141945dc309b94be879fc67835ab3db6b1faad807bca3e21e122184678fe4ea38affe654e15f",  # noqa
    "0x002f302a2d6f3c2a5b53edb53d73c1e3f1771c3b929563c62e74e3330adb0f75b1b164fef915d00aa35b5e668524ef2b"]])  # noqa

BLS12_377_G2_MINUS_8 = G2Point.from_json_list([
    ["0x019ece89be3c82b561d87e7898ddfc928d2e86fafa21febc222d8ff38a752fe95b25e19b25410205800385fb047ca1cf",  # noqa
    "0x016251c985d96e59d07cc363290ec7146682da9bde87ed3d64ccad05403992cc9f3704c7f9a1df34116840d220edba27"],  # noqa
    ["0x0081c573b9f446b86164f1a726c5189f856452533a7cdde3e13cb0350c88cc35d8e97c2217b987023665350019ab1ea2",  # noqa
    "0x017f0a1bea55d4c06ae7180b2f2d875728abbdb76e5fafc8f07e7efcaf2e388a6559f84536ea2ff5e1ad61997adb10d6"]])  # noqa
# pylint: enable=line-too-long


class TestPairing(TestCase):

    def test_pairing_json(self) -> None:
        self._do_test_pairing_json(ALT_BN128_PAIRING)
        self._do_test_pairing_json(BW6_761_PAIRING)
        self._do_test_pairing_json(BLS12_377_PAIRING)

    def test_alt_bn128_negate_g1(self) -> None:
        self._do_test_negate_g1(
            ALT_BN128_PAIRING,
            ALT_BN128_PAIRING.generator_g1,
            ALT_BN128_G1_MINUS_1)
        self._do_test_negate_g1(
            ALT_BN128_PAIRING,
            ALT_BN128_G1_8,
            ALT_BN128_G1_MINUS_8)

    def test_alt_bn128_negate_g2(self) -> None:
        self._do_test_negate_g2(
            ALT_BN128_PAIRING,
            ALT_BN128_PAIRING.generator_g2,
            ALT_BN128_G2_MINUS_1)
        self._do_test_negate_g2(
            ALT_BN128_PAIRING,
            ALT_BN128_G2_8,
            ALT_BN128_G2_MINUS_8)

    def test_bw6_761_negate_g1(self) -> None:
        self._do_test_negate_g1(
            BW6_761_PAIRING,
            BW6_761_PAIRING.generator_g1,
            BW6_761_G1_MINUS_1)
        self._do_test_negate_g1(
            BW6_761_PAIRING,
            BW6_761_G1_8,
            BW6_761_G1_MINUS_8)

    def test_bw6_761_negate_g2(self) -> None:
        self._do_test_negate_g2(
            BW6_761_PAIRING,
            BW6_761_PAIRING.generator_g2,
            BW6_761_G2_MINUS_1)
        self._do_test_negate_g2(
            BW6_761_PAIRING,
            BW6_761_G2_8,
            BW6_761_G2_MINUS_8)

    def test_bls12_377_negate_g1(self) -> None:
        self._do_test_negate_g1(
            BLS12_377_PAIRING,
            BLS12_377_PAIRING.generator_g1,
            BLS12_377_G1_MINUS_1)
        self._do_test_negate_g1(
            BLS12_377_PAIRING,
            BLS12_377_G1_8,
            BLS12_377_G1_MINUS_8)

    def test_bls12_377_negate_g2(self) -> None:
        self._do_test_negate_g2(
            BLS12_377_PAIRING,
            BLS12_377_PAIRING.generator_g2,
            BLS12_377_G2_MINUS_1)
        self._do_test_negate_g2(
            BLS12_377_PAIRING,
            BLS12_377_G2_8,
            BLS12_377_G2_MINUS_8)

    def _do_test_pairing_json(self, pp: PairingParameters) -> None:
        pp_encoded = pp.to_json_dict()
        pp_decoded = PairingParameters.from_json_dict(pp_encoded)
        self.assertEqual(pp.to_json_dict(), pp_decoded.to_json_dict())

    def _do_test_negate_g1(
            self,
            pp: PairingParameters,
            element: G1Point,
            minus_element: G1Point) -> None:
        negated_element = g1_point_negate(element, pp)
        self.assertEqual(minus_element, negated_element)

    def _do_test_negate_g2(
            self,
            pp: PairingParameters,
            element: G2Point,
            minus_element: G2Point) -> None:
        negated_element = g2_point_negate(element, pp)
        self.assertEqual(minus_element, negated_element)
