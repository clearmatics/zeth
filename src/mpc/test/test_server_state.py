#!/usr/bin/env python3

from unittest import TestCase
from coordinator.crypto import import_verification_key
from coordinator.server_state import Configuration, Contributor, ServerState


START_TIME = 8000.0
CONTRIBUTION_INTERVAL = 1000.0


class TestServerState(TestCase):

    def test_configuration(self) -> None:
        config_1 = self._dummy_config()
        config_json_1 = config_1.to_json()
        config_2 = Configuration.from_json(config_json_1)
        config_json_2 = config_2.to_json()
        self.assertEqual(config_json_1, config_json_2)

    def test_state_serialization(self) -> None:
        config = self._dummy_config()
        state = ServerState.new(config)

        # initial state
        self.assertEqual(0, state.next_contributor_index)
        self.assertEqual(
            START_TIME + CONTRIBUTION_INTERVAL,
            state.next_contributor_deadline)

        # json serialization
        self._test_json_serialization(state)

        # update, deadline not passed
        state.update(START_TIME + (CONTRIBUTION_INTERVAL / 2))
        self.assertEqual(0, state.next_contributor_index)
        self.assertEqual(
            START_TIME + CONTRIBUTION_INTERVAL,
            state.next_contributor_deadline)
        self.assertFalse(state.have_all_contributions())

        # json serialization
        self._test_json_serialization(state)

        # deadline passed with no contribution
        state.update(START_TIME + CONTRIBUTION_INTERVAL + 0.1)
        self.assertEqual(1, state.next_contributor_index)
        self.assertEqual(
            START_TIME + 0.1 + 2 * CONTRIBUTION_INTERVAL,
            state.next_contributor_deadline)
        self.assertFalse(state.have_all_contributions())

        # json serialization
        self._test_json_serialization(state)

        # got contribution part way through interval
        state.received_contribution(
            START_TIME + 0.1 + 1.5 * CONTRIBUTION_INTERVAL)
        self.assertEqual(2, state.next_contributor_index)
        self.assertEqual(
            START_TIME + 0.1 + 2.5 * CONTRIBUTION_INTERVAL,
            state.next_contributor_deadline)
        self.assertFalse(state.have_all_contributions())

        # json serialization
        self._test_json_serialization(state)

        # 3rd contribution deadline
        state.update(
            START_TIME + 0.2 + 2.5 * CONTRIBUTION_INTERVAL)
        self.assertEqual(3, state.next_contributor_index)
        self.assertEqual(
            START_TIME + 0.2 + 3.5 * CONTRIBUTION_INTERVAL,
            state.next_contributor_deadline)
        self.assertFalse(state.have_all_contributions())

        # final contribution
        state.received_contribution(
            START_TIME + 0.2 + 3.0 * CONTRIBUTION_INTERVAL)
        self.assertTrue(state.have_all_contributions())
        self.assertEqual(0, state.next_contributor_deadline)

        # json serialization
        self._test_json_serialization(state)

    def _dummy_config(self) -> Configuration:
        TEST_KEY_0 = \
            "30" + \
            "819b301006072a8648ce3d020106052b81040023038186000400da7cc0d36ec6" + \
            "496ff55e2c77df8eb944d452a4b9fed9f73f5ba9e9d01b66dc2d221a8b01f11a" + \
            "f67575b9e8855729e2cf300d8c0addf82a57f0d1396f13117c032b016e7876c2" + \
            "c9c147d1cb72d15e7295e717421a485c17f40a591fe9a1225d73ce7dd77dd545" + \
            "7022f4d22f36960ca0036c1f86f2bec569be98455d44e42169b7b01af2"
        TEST_KEY_1 = \
            "30" + \
            "819b301006072a8648ce3d020106052b810400230381860004017b68c30b536e" + \
            "772d3ad84ff46f9a00225fb93ee693e4ee051c122cf05a37efc384f205a596f3" + \
            "53b5293d8f92aba2ab1319885fff262dd65c8488975097a9963349005d017e20" + \
            "5b32ed016706a75de2461f57f03fefba4d45339cf34271fbd7557b4ec7cca450" + \
            "f04dea14de6500dafb8a193a2647705493a70b03fe1e902737e899c7d4"
        TEST_KEY_2 = \
            "30" + \
            "819b301006072a8648ce3d020106052b81040023038186000401dad8ae45b05e" + \
            "b48d71698636925e422722c908ecdf3c4578a19328a23a5088eab4456b995ee9" + \
            "19091cc82d9b359d39a431af5fd2000b3aa521c3b239c7a638151801ef36d88c" + \
            "5c7bcc99e65dcaacbe2e2cdb1be5fdd5af917e9cb81f5cb74f67a70476c9d501" + \
            "e8254c53fb3bfdcfdc31bcb57d5ae4d041a96de6423c6e0e56a0fb6429"
        TEST_KEY_3 = \
            "30" + \
            "819b301006072a8648ce3d020106052b810400230381860004011ebc2b021f33" + \
            "f2b71ede076c33f38c75b11146db98c2f922f22c79468277315af4c811dbb859" + \
            "f65f3a174a5ca31e42a6a27d63161069f6be46097e5afaddf5617a010671b962" + \
            "7ed80f26ad092a4aef0655dc99e8481946c57dae461daca97fbe32bbb64f3f7f" + \
            "3ed1153420ab0453a9bbfb278a60b5bcdd2ce2efa99c4fd99f63c093b2"
        return Configuration(
            [
                Contributor("c1@mpc.com", import_verification_key(TEST_KEY_0)),
                Contributor("c2@mpc.com", import_verification_key(TEST_KEY_1)),
                Contributor("c3@mpc.com", import_verification_key(TEST_KEY_2)),
                Contributor("c4@mpc.com", import_verification_key(TEST_KEY_3)),
            ],
            START_TIME,
            CONTRIBUTION_INTERVAL)

        pass

    def _test_json_serialization(self, state: ServerState) -> None:
        state_1_json = state.to_json()
        state_2 = ServerState.from_json(state_1_json)
        state_2_json = state_2.to_json()
        self.assertEqual(state_1_json, state_2_json)
