# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.zksnark import IZKSnarkProvider, GenericG1Point, GenericG2Point, \
    IVerificationKey, ExtendedProof, Groth16, group_point_g1_to_proto, \
    group_point_g1_from_proto, group_point_g2_to_proto, group_point_g2_from_proto
from zeth.api import ec_group_messages_pb2
from unittest import TestCase


# pylint: disable=line-too-long
VERIFICATION_KEY_BLS12_377_GROTH16 = Groth16.VerificationKey.from_json_dict({
    "alpha": [
        "0x009d7309d79d5215384a7a9a1d9372af909582781f388a51cb833c87b8024519cf5b343cb35d49a5aa52940f14b7b8e7",  # noqa
        "0x012816ef6069ef1e40eaab0a111f9b98b276dbf2a3209d788eb8ce635ce92a29c2bcdaa3bb9b375a8d3ee4325c07f4ea"  # noqa
    ],
    "beta": [[
        "0x017abb9470ccb0ef09676df87dbe181a9ed89ba1cf1e32a2031d308b4c11a84fd97ac202fb82264cec178e22b71598b9",  # noqa
        "0x01774daba40ce4c9fe2d2c6d17a3821b31ec63a77ebea2dab8b3218fd7eb90f9d561d87ab9712f3bafcf30ed3676553b"  # noqa
    ], [
        "0x00ce3769d0c1e29aa799a5928b1c524a5a85326c4b16463530bfdcab82f55ef6c4649d4916e3c6e5eebd1f8c932b7be1",  # noqa
        "0x009234f3340fb85ae722ed052b8dcf63193c423791d9c43ab725a35286bda1708c3a9d8bff4c1fd55d981c10a30e9cff"  # noqa
    ]],
    "delta": [[
        "0x00c19b1795e634573c0514de0cea5bd05d88c24b08aeadc03ec4686ee6741b80e7dea9065d654a3b703ac8e43173f909",  # noqa
        "0x01a00d16c4d2805e248debf48ea0771e627e2bfb95198df0cbe09a1eb4879fe5fae208347a21c113061921b6a84f7e7d"  # noqa
    ], [
        "0x00361ca07388d760898e0969f3b9a3d6d751b83d770007761e1c5cc798852ed89007ee1504d7c6c7a398693100eef416",  # noqa
        "0x009a7d27c8392eefe1ba23a52d509cda59ba3c5acc95765d1146a998c780277fb318e47a4e4a554d8a3e6f56ccdd2566"  # noqa
    ]],
    "ABC": [[
        "0x001098a772e5fb9edbbd68943000e46bb0f3f2514cbbe1ef15ba485d1c07a683674b5b9398270c1ddf640d345f008353",  # noqa
        "0x018a94eefa95142069e1f1c069d48645201d1201bc0b7d9bc25ee65a25602362fd237f2168b3c9ca0cabd255088312f5"  # noqa
    ], [
        "0x01a4cfba533c731398e06458003ef7c3920dd1a545b469cc0c35dc19c51942c1531b1b9b395c858ee5b381841fc0001c",  # noqa
        "0x006194ebb25bab4d163005b23e9cf9aa8d43d242a7792f0fcf269549b46bcc2172443d09bbe573cb5eba60c9c97737c6"  # noqa
    ]]
})

# Encoded as evm uint256_t words
VERIFICATION_KEY_BLS12_377_GROTH16_PARAMETERS = [
    # Alpha
    int("00000000000000000000000000000000009d7309d79d5215384a7a9a1d9372af", 16),  # noqa
    int("909582781f388a51cb833c87b8024519cf5b343cb35d49a5aa52940f14b7b8e7", 16),  # noqa
    int("00000000000000000000000000000000012816ef6069ef1e40eaab0a111f9b98", 16),  # noqa
    int("b276dbf2a3209d788eb8ce635ce92a29c2bcdaa3bb9b375a8d3ee4325c07f4ea", 16),  # noqa
    # Beta1
    int("00000000000000000000000000000000017abb9470ccb0ef09676df87dbe181a", 16),  # noqa
    int("9ed89ba1cf1e32a2031d308b4c11a84fd97ac202fb82264cec178e22b71598b9", 16),  # noqa
    int("0000000000000000000000000000000001774daba40ce4c9fe2d2c6d17a3821b", 16),  # noqa
    int("31ec63a77ebea2dab8b3218fd7eb90f9d561d87ab9712f3bafcf30ed3676553b", 16),  # noqa
    int("0000000000000000000000000000000000ce3769d0c1e29aa799a5928b1c524a", 16),  # noqa
    int("5a85326c4b16463530bfdcab82f55ef6c4649d4916e3c6e5eebd1f8c932b7be1", 16),  # noqa
    int("00000000000000000000000000000000009234f3340fb85ae722ed052b8dcf63", 16),  # noqa
    int("193c423791d9c43ab725a35286bda1708c3a9d8bff4c1fd55d981c10a30e9cff", 16),  # noqa
    # Delta
    int("0000000000000000000000000000000000c19b1795e634573c0514de0cea5bd0", 16),  # noqa
    int("5d88c24b08aeadc03ec4686ee6741b80e7dea9065d654a3b703ac8e43173f909", 16),  # noqa
    int("0000000000000000000000000000000001a00d16c4d2805e248debf48ea0771e", 16),  # noqa
    int("627e2bfb95198df0cbe09a1eb4879fe5fae208347a21c113061921b6a84f7e7d", 16),  # noqa
    int("0000000000000000000000000000000000361ca07388d760898e0969f3b9a3d6", 16),  # noqa
    int("d751b83d770007761e1c5cc798852ed89007ee1504d7c6c7a398693100eef416", 16),  # noqa
    int("00000000000000000000000000000000009a7d27c8392eefe1ba23a52d509cda", 16),  # noqa
    int("59ba3c5acc95765d1146a998c780277fb318e47a4e4a554d8a3e6f56ccdd2566", 16),  # noqa
    # ABC
    int("00000000000000000000000000000000001098a772e5fb9edbbd68943000e46b", 16),  # noqa
    int("b0f3f2514cbbe1ef15ba485d1c07a683674b5b9398270c1ddf640d345f008353", 16),  # noqa
    int("00000000000000000000000000000000018a94eefa95142069e1f1c069d48645", 16),  # noqa
    int("201d1201bc0b7d9bc25ee65a25602362fd237f2168b3c9ca0cabd255088312f5", 16),  # noqa
    int("0000000000000000000000000000000001a4cfba533c731398e06458003ef7c3", 16),  # noqa
    int("920dd1a545b469cc0c35dc19c51942c1531b1b9b395c858ee5b381841fc0001c", 16),  # noqa
    int("00000000000000000000000000000000006194ebb25bab4d163005b23e9cf9aa", 16),  # noqa
    int("8d43d242a7792f0fcf269549b46bcc2172443d09bbe573cb5eba60c9c97737c6", 16),  # noqa
]

VERIFICATION_KEY_BW6_761_GROTH16 = Groth16.VerificationKey.from_json_dict({
    "alpha": [
        "0x00b1cb8971a538e5086e12fd7ce423b9611a6eee1ce9ec95fb966bf333c72d71e16a5f6ab1ffa0b68a3bd99ad263d036c80d6d854934d20b4e322e06df34dce5ad1ab5855aa1a13ee2fc340a22a4ee9b07acf7198e9b76904f12248a45c15267",  # noqa
        "0x010029659098127958344df7ae0d96e411c163df75454032fa940b7b25cf82b98f167e311eb6fc392551d9d2e87a1c7fc7b022f967f455dd0d60c0dba6943a2d77c30768bec0349c8351039aef0709c2af413e6ee2dfd13ed418392d06c3f2ff"  # noqa
    ],
    "beta": [
        "0x00a172034ccac6782c351ac3a91341b3792d589254c6e8bee9c7becf276bc51fbaf9d19645f10d8e4598978a14fb4fb46a7dba2213c47f921d5dfc0318866d5ce561f69fbabbd1edc3d6fa3f8c4514edb6ab0c93bdd4285e5a25153218fbaa79",  # noqa
        "0x00f96a865caa92048ea60ebd5cf3890b3f550b25597bf304be34ea4dbceb2021407975d68a3c0511fa5b039563fbdc34e1a49c4b11766b6c00f4c2592d5c8529a56f4d6840730a40e617cd7dfa007df86ffb7dcfea67779d319b798be47c6546"  # noqa
    ],
    "delta": [
        "0x00118a94304763b5706df5a38316fac1520597604e0c5f3263b4f8ec2787852230d3b69785b6817b47874b98ec249b261499f05d95183e95ce7035b28cbdab37b21811b7b6ec7f11bd938d994b219b85fc689516061cfbfad168b86caa71a1de",  # noqa
        "0x00ae6e5f4cb84b5849d74a4fef5f417c9a52830346cc4967f662b48ff948bf3f08889c47cd7041773759fb1dc4140edbc452043e43ed93156eb098f5d4749d625fcd68b6d5c49caaab443fbf8b8d38e9a4ddd96ddaa8936cd95dfe44a6cb7ebf"  # noqa
    ],
    "ABC": [[
        "0x0042ab364724f3229d715738ad4bd7c405725eb5161704aa077a84983d44df7bfad3111b20f9e8d16691b8e2743f1269649fbadbd55275fdf4108d68e9f62f1f52c84e8fd4ab2e2b33d90fe359b41a84a39c34605e0c9cafa2b29e6d801c1b33",  # noqa
        "0x011bad78d591fae2b880bbdcdbaef44fa2ef6cba9f4d20f503879083d9a8cdf401100686ea3ed9097f523ef7c5ea4d5fdf64babcdaea8dbd0c374296f8420b2afe694df07fc80f948cc9e7d2ddb12494dc8f7580befc4bc4d5c7b5c44fc79cca"  # noqa
    ], [
        "0x011a389bf2766b1d4d07c47eaacc85b5672e12cf68ad50ed59f3d4b5a5fd8d45e2f8d375cc3c323f48c70dc40d1b900e694bd305efb9b98706b73ecc308ba1c7d623f158b326973c50caa1b45c167c2a719a047b3cb187869cbcba35c85a1318",  # noqa
        "0x000a0d6b9918419c5e04cffd000ef5fc6faa297c95b9f0246ed5f680b301b98f564c8f55dc8cf17fd521d2f02d80bc7b372db677a8a5fffad98d28888fd2770af1ecb70978527c885c3d255fb2d2c4df30b54775748e15ab4f2d4b61f0f21720"  # noqa
    ], [
        "0x01148f36b74959ed38685e4e82390211d51df06e2b2f9f8b317aa181f4977220859da56b7eec940a62152d19804540331e66aba57e15cab8092c1f466704befc5b83c6ca289dc37f8845c9ca4999d69b019d2d1aa21bd5f2d406dd04ed5382b5",  # noqa
        "0x007798f8a88ba7814fdb15fe227afdf8e0e45faa4ce81b3ce5128c233d7d5d7269c8fcfd22cb65bdc5c2002a239feb4fd36bc94de8d8e7b79d6ff553c06eec1277bbbc0f5161e86035409db95353858f354ca57f19a432f1c21b8f57415114cc"  # noqa
    ], [
        "0x00eb3befd2036ac7e53f694b20b3049f1fa76335e3c40e5fc1058fcc8bac3c76d54f386e015bce8a99a9bb66c1e25bb84370acf00496985ec2011146696d431cf34e957b83b8155bea2260a48dd2889a3161cb590b6ccbb97013b293b7946dbd",  # noqa
        "0x00b8f338e7ba352f552a4d95adba7d02f9b39f7de009a7b79b14962694f05f134634f1d2b9f518045da23bc06a31bb509880f7048a170e4cde8c7c59409ae723c2aa4f97619b2795f6ef1a664784b7e3b7d525251529ae105045f08192de1284"  # noqa
    ], [
        "0x005c4da704dbda589aa9de33e78d6aafc39b4621165760d68e4aa7c6a02405a76d06420139474103cc3934b5bdba50f0fbdcfcdf87840bfde8ab116b4574156375be5d98f8234a118843cd9e45671bff74894bc0f6643f269d0f718b48b66779",  # noqa
        "0x00cd4a69bea6754acadb3e48e081311e563b9bc3f516ee8bf9f255dfa14ac350fb858bb26ac194e5120591160aff2545e59d0c319950a271fde2f43c98e54153f0f15aaab49b8a3d72d2cf1a6ba43e567e15f9de19ef2f84ecaeda04c8101c59"  # noqa
    ], [
        "0x00640ff3df8bcd82d341de6e7adbf4bc12a06138a7555c28febd8baf55e5898e70b2c814863ed3a381215c2ad84eb57d5790cd6a1b0ce83654e4b1a22bf861f6218efd9207108c0fd78899bd292eac0dcfdecf5f88ca2cde6abad08959957424",  # noqa
        "0x0103a02dbd8b63bd1290b2f1e9471bb9206a3ade95bf5723f49cb8b9c47606836f3173d38bf060fc367df04048635714525a37354205a598e55fafba3485b1333e6bbde6504fcf291ae9f319d1b908e06510b70eef72916a5447b84a01d62f49"  # noqa
    ]]
})

VERIFICATION_KEY_BW6_761_GROTH16_PARAMETERS = [
    # "alpha":
    int("00b1cb8971a538e5086e12fd7ce423b9611a6eee1ce9ec95fb966bf333c72d71", 16),  # noqa
    int("e16a5f6ab1ffa0b68a3bd99ad263d036c80d6d854934d20b4e322e06df34dce5", 16),  # noqa
    int("ad1ab5855aa1a13ee2fc340a22a4ee9b07acf7198e9b76904f12248a45c15267", 16),  # noqa
    int("010029659098127958344df7ae0d96e411c163df75454032fa940b7b25cf82b9", 16),  # noqa
    int("8f167e311eb6fc392551d9d2e87a1c7fc7b022f967f455dd0d60c0dba6943a2d", 16),  # noqa
    int("77c30768bec0349c8351039aef0709c2af413e6ee2dfd13ed418392d06c3f2ff", 16),  # noqa
    # "beta":
        int("00a172034ccac6782c351ac3a91341b3792d589254c6e8bee9c7becf276bc51f", 16),  # noqa
    int("baf9d19645f10d8e4598978a14fb4fb46a7dba2213c47f921d5dfc0318866d5c", 16),  # noqa
    int("e561f69fbabbd1edc3d6fa3f8c4514edb6ab0c93bdd4285e5a25153218fbaa79", 16),  # noqa
    int("00f96a865caa92048ea60ebd5cf3890b3f550b25597bf304be34ea4dbceb2021", 16),  # noqa
    int("407975d68a3c0511fa5b039563fbdc34e1a49c4b11766b6c00f4c2592d5c8529", 16),  # noqa
    int("a56f4d6840730a40e617cd7dfa007df86ffb7dcfea67779d319b798be47c6546", 16),  # noqa
    # "delta":
    int("00118a94304763b5706df5a38316fac1520597604e0c5f3263b4f8ec27878522", 16),  # noqa
    int("30d3b69785b6817b47874b98ec249b261499f05d95183e95ce7035b28cbdab37", 16),  # noqa
    int("b21811b7b6ec7f11bd938d994b219b85fc689516061cfbfad168b86caa71a1de", 16),  # noqa
    int("00ae6e5f4cb84b5849d74a4fef5f417c9a52830346cc4967f662b48ff948bf3f", 16),  # noqa
    int("08889c47cd7041773759fb1dc4140edbc452043e43ed93156eb098f5d4749d62", 16),  # noqa
    int("5fcd68b6d5c49caaab443fbf8b8d38e9a4ddd96ddaa8936cd95dfe44a6cb7ebf", 16),  # noqa
    # "ABC":
    int("0042ab364724f3229d715738ad4bd7c405725eb5161704aa077a84983d44df7b", 16),  # noqa
    int("fad3111b20f9e8d16691b8e2743f1269649fbadbd55275fdf4108d68e9f62f1f", 16),  # noqa
    int("52c84e8fd4ab2e2b33d90fe359b41a84a39c34605e0c9cafa2b29e6d801c1b33", 16),  # noqa
    int("011bad78d591fae2b880bbdcdbaef44fa2ef6cba9f4d20f503879083d9a8cdf4", 16),  # noqa
    int("01100686ea3ed9097f523ef7c5ea4d5fdf64babcdaea8dbd0c374296f8420b2a", 16),  # noqa
    int("fe694df07fc80f948cc9e7d2ddb12494dc8f7580befc4bc4d5c7b5c44fc79cca", 16),  # noqa
    int("011a389bf2766b1d4d07c47eaacc85b5672e12cf68ad50ed59f3d4b5a5fd8d45", 16),  # noqa
    int("e2f8d375cc3c323f48c70dc40d1b900e694bd305efb9b98706b73ecc308ba1c7", 16),  # noqa
    int("d623f158b326973c50caa1b45c167c2a719a047b3cb187869cbcba35c85a1318", 16),  # noqa
    int("000a0d6b9918419c5e04cffd000ef5fc6faa297c95b9f0246ed5f680b301b98f", 16),  # noqa
    int("564c8f55dc8cf17fd521d2f02d80bc7b372db677a8a5fffad98d28888fd2770a", 16),  # noqa
    int("f1ecb70978527c885c3d255fb2d2c4df30b54775748e15ab4f2d4b61f0f21720", 16),  # noqa
    int("01148f36b74959ed38685e4e82390211d51df06e2b2f9f8b317aa181f4977220", 16),  # noqa
    int("859da56b7eec940a62152d19804540331e66aba57e15cab8092c1f466704befc", 16),  # noqa
    int("5b83c6ca289dc37f8845c9ca4999d69b019d2d1aa21bd5f2d406dd04ed5382b5", 16),  # noqa
    int("007798f8a88ba7814fdb15fe227afdf8e0e45faa4ce81b3ce5128c233d7d5d72", 16),  # noqa
    int("69c8fcfd22cb65bdc5c2002a239feb4fd36bc94de8d8e7b79d6ff553c06eec12", 16),  # noqa
    int("77bbbc0f5161e86035409db95353858f354ca57f19a432f1c21b8f57415114cc", 16),  # noqa
    int("00eb3befd2036ac7e53f694b20b3049f1fa76335e3c40e5fc1058fcc8bac3c76", 16),  # noqa
    int("d54f386e015bce8a99a9bb66c1e25bb84370acf00496985ec2011146696d431c", 16),  # noqa
    int("f34e957b83b8155bea2260a48dd2889a3161cb590b6ccbb97013b293b7946dbd", 16),  # noqa
    int("00b8f338e7ba352f552a4d95adba7d02f9b39f7de009a7b79b14962694f05f13", 16),  # noqa
    int("4634f1d2b9f518045da23bc06a31bb509880f7048a170e4cde8c7c59409ae723", 16),  # noqa
    int("c2aa4f97619b2795f6ef1a664784b7e3b7d525251529ae105045f08192de1284", 16),  # noqa
    int("005c4da704dbda589aa9de33e78d6aafc39b4621165760d68e4aa7c6a02405a7", 16),  # noqa
    int("6d06420139474103cc3934b5bdba50f0fbdcfcdf87840bfde8ab116b45741563", 16),  # noqa
    int("75be5d98f8234a118843cd9e45671bff74894bc0f6643f269d0f718b48b66779", 16),  # noqa
    int("00cd4a69bea6754acadb3e48e081311e563b9bc3f516ee8bf9f255dfa14ac350", 16),  # noqa
    int("fb858bb26ac194e5120591160aff2545e59d0c319950a271fde2f43c98e54153", 16),  # noqa
    int("f0f15aaab49b8a3d72d2cf1a6ba43e567e15f9de19ef2f84ecaeda04c8101c59", 16),  # noqa
    int("00640ff3df8bcd82d341de6e7adbf4bc12a06138a7555c28febd8baf55e5898e", 16),  # noqa
    int("70b2c814863ed3a381215c2ad84eb57d5790cd6a1b0ce83654e4b1a22bf861f6", 16),  # noqa
    int("218efd9207108c0fd78899bd292eac0dcfdecf5f88ca2cde6abad08959957424", 16),  # noqa
    int("0103a02dbd8b63bd1290b2f1e9471bb9206a3ade95bf5723f49cb8b9c4760683", 16),  # noqa
    int("6f3173d38bf060fc367df04048635714525a37354205a598e55fafba3485b133", 16),  # noqa
    int("3e6bbde6504fcf291ae9f319d1b908e06510b70eef72916a5447b84a01d62f49", 16),  # noqa
]

VERIFICATION_KEY_ALT_BN128_GROTH16 = Groth16.VerificationKey.from_json_dict({
    "alpha": [
        "0x009d7309d79d5215384a7a9a1d9372af909582781f388a51cb833c87b8024519",
        "0x012816ef6069ef1e40eaab0a111f9b98b276dbf2a3209d788eb8ce635ce92a29",
    ],
    "beta": [[
        "0x017abb9470ccb0ef09676df87dbe181a9ed89ba1cf1e32a2031d308b4c11a84f",
        "0x01774daba40ce4c9fe2d2c6d17a3821b31ec63a77ebea2dab8b3218fd7eb90f9",
    ], [
        "0x18ce3769d0c1e29aa799a5928b1c524a5a85326c4b16463530bfdcab82f55ef6",
        "0x1a9234f3340fb85ae722ed052b8dcf63193c423791d9c43ab725a35286bda170",
    ]],
    "delta": [[
        "0x19c19b1795e634573c0514de0cea5bd05d88c24b08aeadc03ec4686ee6741b80",
        "0x01a00d16c4d2805e248debf48ea0771e627e2bfb95198df0cbe09a1eb4879fe5",
    ], [
        "0x00361ca07388d760898e0969f3b9a3d6d751b83d770007761e1c5cc798852ed8",
        "0x009a7d27c8392eefe1ba23a52d509cda59ba3c5acc95765d1146a998c780277f",
    ]],
    "ABC": [[
        "0x01098a772e5fb9edbbd68943000e46bb0f3f2514cbbe1ef15ba485d1c07a6836",
        "0x18a94eefa95142069e1f1c069d48645201d1201bc0b7d9bc25ee65a25602362f",
    ], [
        "0x1a4cfba533c731398e06458003ef7c3920dd1a545b469cc0c35dc19c51942c15",
        "0x06194ebb25bab4d163005b23e9cf9aa8d43d242a7792f0fcf269549b46bcc217",
    ]]
})

# Encoded as evm uint256_t words
VERIFICATION_KEY_ALT_BN128_GROTH16_PARAMETERS = [
    # Alpha
    int("0x009d7309d79d5215384a7a9a1d9372af909582781f388a51cb833c87b8024519", 16),  # noqa
    int("0x012816ef6069ef1e40eaab0a111f9b98b276dbf2a3209d788eb8ce635ce92a29", 16),  # noqa
    # Beta1
    int("0x017abb9470ccb0ef09676df87dbe181a9ed89ba1cf1e32a2031d308b4c11a84f", 16),  # noqa
    int("0x01774daba40ce4c9fe2d2c6d17a3821b31ec63a77ebea2dab8b3218fd7eb90f9", 16),  # noqa
    int("0x18ce3769d0c1e29aa799a5928b1c524a5a85326c4b16463530bfdcab82f55ef6", 16),  # noqa
    int("0x1a9234f3340fb85ae722ed052b8dcf63193c423791d9c43ab725a35286bda170", 16),  # noqa
    # Delta
    int("0x19c19b1795e634573c0514de0cea5bd05d88c24b08aeadc03ec4686ee6741b80", 16),  # noqa
    int("0x01a00d16c4d2805e248debf48ea0771e627e2bfb95198df0cbe09a1eb4879fe5", 16),  # noqa
    int("0x00361ca07388d760898e0969f3b9a3d6d751b83d770007761e1c5cc798852ed8", 16),  # noqa
    int("0x009a7d27c8392eefe1ba23a52d509cda59ba3c5acc95765d1146a998c780277f", 16),  # noqa
    # ABC
    int("0x01098a772e5fb9edbbd68943000e46bb0f3f2514cbbe1ef15ba485d1c07a6836", 16),  # noqa
    int("0x18a94eefa95142069e1f1c069d48645201d1201bc0b7d9bc25ee65a25602362f", 16),  # noqa
    int("0x1a4cfba533c731398e06458003ef7c3920dd1a545b469cc0c35dc19c51942c15", 16),  # noqa
    int("0x06194ebb25bab4d163005b23e9cf9aa8d43d242a7792f0fcf269549b46bcc217", 16),  # noqa
]

EXTPROOF_BLS12_377_GROTH16 = ExtendedProof(
    proof=Groth16.Proof.from_json_dict({
        "a": [
            "0x010bd3c06ed5aeb1a7b0653ba63f413b27ba7fd1b77cb4a403fb15f9fb8735abda93a3c78ad05afd111ea68d016cf99e",  # noqa
            "0x00255a73b1247dcfd62171b29ddbd271cdb7e98b78912ddf6bfe4723cd229f414f9a47cecd0fec7fb74bf13b22a7395b"  # noqa
        ],
        "minus_b": [
            [
                "0x01ada9239a53b094ae15473baaa3649afb46d5330f36f8590df668167dd02aaf0a18602ce42654c3d857c4e5e454ca28",  # noqa
                "0x00938ce5525864aa135674b048bb68adadfabca2a4cea43ea13b19cacec1ae171986009e916f729a085c04cbe22c4127"  # noqa
            ],
            [
                "0x01015a4ea0daaaf8ef20b37c4bda03c2d381be797ae59b621b841d3e61495cf2aaf7e008565884f1d7245ea003ebbf79",  # noqa
                "0x0128d64383293780f481278fbb22ce1078d79180193361869d9e8639f028ac4c3a7c12f8bc7f7c138821bccd71abcca5"  # noqa
            ]
        ],
        "c": [
            "0x00001c5d91872102ab1ca71b321f5e3b6aca698be9d8b432b8f1fc60c37bda88d6f9fdcc91225dd2d17bc58f08826e68",  # noqa
            "0x000b34a2d07bba78abf1c3e909b1f691bb02f62991a6c6bab53c016e191ecf7929f866eef5231e7f0d29944166a49bf1"  # noqa
        ]
    }),
    inputs=[
        "0x0000000000000000000000000000000000000000000000000000000000000007"  # noqa
    ])

# Proof part of EXTPROOF_BLS12_377_GROTH16 encoded as uint256_t words
PROOF_BLS12_377_GROTH16_PARAMETERS = [
    # "a":
    int("00000000000000000000000000000000010bd3c06ed5aeb1a7b0653ba63f413b", 16),  # noqa
    int("27ba7fd1b77cb4a403fb15f9fb8735abda93a3c78ad05afd111ea68d016cf99e", 16),  # noqa
    int("0000000000000000000000000000000000255a73b1247dcfd62171b29ddbd271", 16),  # noqa
    int("cdb7e98b78912ddf6bfe4723cd229f414f9a47cecd0fec7fb74bf13b22a7395b", 16),  # noqa
    # "minus_b":
    int("0000000000000000000000000000000001ada9239a53b094ae15473baaa3649a", 16),  # noqa
    int("fb46d5330f36f8590df668167dd02aaf0a18602ce42654c3d857c4e5e454ca28", 16),  # noqa
    int("0000000000000000000000000000000000938ce5525864aa135674b048bb68ad", 16),  # noqa
    int("adfabca2a4cea43ea13b19cacec1ae171986009e916f729a085c04cbe22c4127", 16),  # noqa
    int("0000000000000000000000000000000001015a4ea0daaaf8ef20b37c4bda03c2", 16),  # noqa
    int("d381be797ae59b621b841d3e61495cf2aaf7e008565884f1d7245ea003ebbf79", 16),  # noqa
    int("000000000000000000000000000000000128d64383293780f481278fbb22ce10", 16),  # noqa
    int("78d79180193361869d9e8639f028ac4c3a7c12f8bc7f7c138821bccd71abcca5", 16),  # noqa
    # "c":
    int("0000000000000000000000000000000000001c5d91872102ab1ca71b321f5e3b", 16),  # noqa
    int("6aca698be9d8b432b8f1fc60c37bda88d6f9fdcc91225dd2d17bc58f08826e68", 16),  # noqa
    int("00000000000000000000000000000000000b34a2d07bba78abf1c3e909b1f691", 16),  # noqa
    int("bb02f62991a6c6bab53c016e191ecf7929f866eef5231e7f0d29944166a49bf1", 16),  # noqa
]

EXTPROOF_BW6_761_GROTH16 = ExtendedProof(
    proof=Groth16.Proof.from_json_dict({
        "a": [
            "0x00b42fc65c4178e23c5ea46791b63f13e01057d957d097d2a7b1b99b921b3db0b519b21bd21f9d5209420de0d39e6ceebcf40df23e8f3dfb3544e3f221687a254f935e7e4eafbded993af4464cf7ca8da374b2cbcc6003fb47bc590dd8eaadc2",  # noqa
            "0x001f63f85f5e96168363e1c3733094347b9d7d0cbb2b762c65c12b52fe92e126b1f884d331d7b8740dccb383d7565eeb625fc43598bd371801153e0a690e1881f84849653fce01034cb571b78232b5e7aab22f0b3ee089c0b907de8a52628a92"  # noqa
        ],
        "minus_b": [
            "0x00bfb5be9eb134d7118ab1f759b5a801dda03315108848082a6815dab0c88fe253429d65b7b03a7983a6ee353f0f9687de39888afe4fcb106900a10cee2c4c42d6efa2ee7cdc8d82b052fa8e0f79786d2a4847a25d9ca9026a106de6c73c8d18",  # noqa
            "0x00b9f29ad8d2107e760fa728a897b26b673e3b099e56e7c2bdfe0194cd02f8aff4b799f6f8d07f6e3b7dfc000e02eda978e1993a57337b5e2f2e9e3f024ef30367887ed23cca57cc33d8bfafdfb4c914e085870621cf02bb380b80387162fb40"  # noqa
        ],
        "c": [
            "0x003f75f402703fb7d597cd9beb33fb216af606a687c133ef8b73fde17a48c12be3f17867679ccd5958ceb9245adac2377eb1444c6577049f04c0a18645b00a4bae9c6274cd8876f52f5307dfc50935b5f515ee33c5e98031705fe4ce153da553",  # noqa
            "0x00c83d865b8c18f4120fdc9f45026e252d05ceb3f0dfcd19a8e2f11d2a8cd6cdb7450c0fc8e0b1a284db1c21d25d9fbea91d741713f414f577ccb8455e1c55af07b72c4868e58c9890c0335bf13a5821391f0cc8c38ab1f168314f1cb67b10a1"  # noqa
        ]
    }),
    inputs=[
        "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",  # noqa
        "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007",  # noqa
        "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",  # noqa
        "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008",  # noqa
        "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"  # noqa
    ])

PROOF_BW6_761_GROTH16_PARAMETERS = [
    # "a":
    int("00b42fc65c4178e23c5ea46791b63f13e01057d957d097d2a7b1b99b921b3db0", 16),  # noqa
    int("b519b21bd21f9d5209420de0d39e6ceebcf40df23e8f3dfb3544e3f221687a25", 16),  # noqa
    int("4f935e7e4eafbded993af4464cf7ca8da374b2cbcc6003fb47bc590dd8eaadc2", 16),  # noqa
    int("001f63f85f5e96168363e1c3733094347b9d7d0cbb2b762c65c12b52fe92e126", 16),  # noqa
    int("b1f884d331d7b8740dccb383d7565eeb625fc43598bd371801153e0a690e1881", 16),  # noqa
    int("f84849653fce01034cb571b78232b5e7aab22f0b3ee089c0b907de8a52628a92", 16),  # noqa
    # "minus_b":
    int("00bfb5be9eb134d7118ab1f759b5a801dda03315108848082a6815dab0c88fe2", 16),  # noqa
    int("53429d65b7b03a7983a6ee353f0f9687de39888afe4fcb106900a10cee2c4c42", 16),  # noqa
    int("d6efa2ee7cdc8d82b052fa8e0f79786d2a4847a25d9ca9026a106de6c73c8d18", 16),  # noqa
    int("00b9f29ad8d2107e760fa728a897b26b673e3b099e56e7c2bdfe0194cd02f8af", 16),  # noqa
    int("f4b799f6f8d07f6e3b7dfc000e02eda978e1993a57337b5e2f2e9e3f024ef303", 16),  # noqa
    int("67887ed23cca57cc33d8bfafdfb4c914e085870621cf02bb380b80387162fb40", 16),  # noqa
    # "c":
    int("003f75f402703fb7d597cd9beb33fb216af606a687c133ef8b73fde17a48c12b", 16),  # noqa
    int("e3f17867679ccd5958ceb9245adac2377eb1444c6577049f04c0a18645b00a4b", 16),  # noqa
    int("ae9c6274cd8876f52f5307dfc50935b5f515ee33c5e98031705fe4ce153da553", 16),  # noqa
    int("00c83d865b8c18f4120fdc9f45026e252d05ceb3f0dfcd19a8e2f11d2a8cd6cd", 16),  # noqa
    int("b7450c0fc8e0b1a284db1c21d25d9fbea91d741713f414f577ccb8455e1c55af", 16),  # noqa
    int("07b72c4868e58c9890c0335bf13a5821391f0cc8c38ab1f168314f1cb67b10a1", 16),  # noqa
]

EXTPROOF_ALT_BN128_GROTH16 = ExtendedProof(
    proof=Groth16.Proof.from_json_dict({
        "a": [
            "0xbd3c06ed5aeb1a7b0653ba63f413b27ba7fd1b77cb4a403fb15f9fb8735abda9",  # noqa
            "0x55a73b1247dcfd62171b29ddbd271cdb7e98b78912ddf6bfe4723cd229f414f9"  # noqa
        ],
        "minus_b": [
            [
                "0xda9239a53b094ae15473baaa3649afb46d5330f36f8590df668167dd02aaf0a1",  # noqa
                "0x38ce5525864aa135674b048bb68adadfabca2a4cea43ea13b19cacec1ae17198"  # noqa
            ],
            [
                "0x15a4ea0daaaf8ef20b37c4bda03c2d381be797ae59b621b841d3e61495cf2aaf",  # noqa
                "0x8d64383293780f481278fbb22ce1078d79180193361869d9e8639f028ac4c3a7"  # noqa
            ]
        ],
        "c": [
            "0x01c5d91872102ab1ca71b321f5e3b6aca698be9d8b432b8f1fc60c37bda88d6f",  # noqa
            "0xb34a2d07bba78abf1c3e909b1f691bb02f62991a6c6bab53c016e191ecf7929f"  # noqa
        ]
    }),
    inputs=[
        "0x0000000000000000000000000000000000000000000000000000000000000007"  # noqa
    ])

# Proof part of EXTPROOF_BLS12_377_GROTH16 encoded as uint256_t words
PROOF_ALT_BN128_GROTH16_PARAMETERS = [
    # "a":
    int("0xbd3c06ed5aeb1a7b0653ba63f413b27ba7fd1b77cb4a403fb15f9fb8735abda9", 16),  # noqa
    int("0x55a73b1247dcfd62171b29ddbd271cdb7e98b78912ddf6bfe4723cd229f414f9", 16),  # noqa
    # "minus_b":
    int("0xda9239a53b094ae15473baaa3649afb46d5330f36f8590df668167dd02aaf0a1", 16),  # noqa
    int("0x38ce5525864aa135674b048bb68adadfabca2a4cea43ea13b19cacec1ae17198", 16),  # noqa
    int("0x15a4ea0daaaf8ef20b37c4bda03c2d381be797ae59b621b841d3e61495cf2aaf", 16),  # noqa
    int("0x8d64383293780f481278fbb22ce1078d79180193361869d9e8639f028ac4c3a7", 16),  # noqa
    # "c":
    int("0x01c5d91872102ab1ca71b321f5e3b6aca698be9d8b432b8f1fc60c37bda88d6f", 16),  # noqa
    int("0xb34a2d07bba78abf1c3e909b1f691bb02f62991a6c6bab53c016e191ecf7929f", 16),  # noqa
]
# pylint: enable=line-too-long


class TestZKSnark(TestCase):

    def test_bls12_377_groth16_verification_key_parameters(self) -> None:
        vk = VERIFICATION_KEY_BLS12_377_GROTH16
        vk_parameters_expect = VERIFICATION_KEY_BLS12_377_GROTH16_PARAMETERS
        vk_parameters = Groth16.verification_key_to_contract_parameters(vk)
        self.assertEqual(vk_parameters_expect, vk_parameters)

    def test_bls12_377_groth16_proof_parameters(self) -> None:
        extproof = EXTPROOF_BLS12_377_GROTH16
        proof_parameters = Groth16.proof_to_contract_parameters(extproof.proof)
        self.assertEqual(PROOF_BLS12_377_GROTH16_PARAMETERS, proof_parameters)

    def test_bw6_761_groth16_verification_key_parameters(self) -> None:
        vk = VERIFICATION_KEY_BW6_761_GROTH16
        vk_parameters_expect = VERIFICATION_KEY_BW6_761_GROTH16_PARAMETERS
        vk_parameters = Groth16.verification_key_to_contract_parameters(vk)
        self.assertEqual(vk_parameters_expect, vk_parameters)

    def test_bw6_761_groth16_proof_parameters(self) -> None:
        extproof = EXTPROOF_BW6_761_GROTH16
        proof_parameters = Groth16.proof_to_contract_parameters(extproof.proof)
        self.assertEqual(PROOF_BW6_761_GROTH16_PARAMETERS, proof_parameters)

    def test_alt_bn128_groth16_verification_key_parameters(self) -> None:
        vk = VERIFICATION_KEY_ALT_BN128_GROTH16
        vk_parameters_expect = VERIFICATION_KEY_ALT_BN128_GROTH16_PARAMETERS
        vk_parameters = Groth16.verification_key_to_contract_parameters(vk)
        self.assertEqual(vk_parameters_expect, vk_parameters)

    def test_alt_bn128_groth16_proof_parameters(self) -> None:
        extproof = EXTPROOF_ALT_BN128_GROTH16
        proof_parameters = Groth16.proof_to_contract_parameters(extproof.proof)
        self.assertEqual(PROOF_ALT_BN128_GROTH16_PARAMETERS, proof_parameters)

    def test_g1_proto_encode_decode(self) -> None:
        self._do_test_g1_proto_encode_decode(
            GenericG1Point("0xaabbccdd", "0x11223344"))

    def test_g2_proto_encode_decode(self) -> None:
        self._do_test_g2_proto_encode_decode(
            GenericG2Point("0xaabbccdd", "0x11223344"))
        self._do_test_g2_proto_encode_decode(
            GenericG2Point(
                ["0xcdeeff00", "0x11223344"], ["0x55667788", "0x99aabbcc"]))

    def test_verification_key_proto_encode_decode(self) -> None:
        vk_1 = VERIFICATION_KEY_BLS12_377_GROTH16
        self._do_test_verification_key_proto_encode_decode(vk_1, Groth16())

    def test_proof_proto_encode_decode(self) -> None:
        extproof_1 = EXTPROOF_BLS12_377_GROTH16
        self._do_test_ext_proof_proto_encode_decode(extproof_1, Groth16())

    def _do_test_g1_proto_encode_decode(self, g1: GenericG1Point) -> None:
        g1_proto = ec_group_messages_pb2.Group1Point()
        group_point_g1_to_proto(g1, g1_proto)
        g1_decoded = group_point_g1_from_proto(g1_proto)
        self.assertEqual(g1.to_json_list(), g1_decoded.to_json_list())

    def _do_test_g2_proto_encode_decode(self, g2: GenericG2Point) -> None:
        g2_proto = ec_group_messages_pb2.Group2Point()
        group_point_g2_to_proto(g2, g2_proto)
        g2_decoded = group_point_g2_from_proto(g2_proto)
        self.assertEqual(g2.to_json_list(), g2_decoded.to_json_list())

    def _do_test_verification_key_proto_encode_decode(
            self,
            vk: IVerificationKey,
            snark: IZKSnarkProvider) -> None:
        vk_proto = snark.verification_key_to_proto(vk)
        vk_decoded = snark.verification_key_from_proto(vk_proto)
        # For now, compare as json to brush over tuple-list differences.
        self.assertEqual(vk.to_json_dict(), vk_decoded.to_json_dict())

    def _do_test_ext_proof_proto_encode_decode(
            self, proof: ExtendedProof, snark: IZKSnarkProvider) -> None:
        proof_proto = snark.extended_proof_to_proto(proof)
        proof_decoded = snark.extended_proof_from_proto(proof_proto)
        self.assertEqual(proof.to_json_dict(), proof_decoded.to_json_dict())
