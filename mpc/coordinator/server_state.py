#!/usr/bin/env python3

from __future__ import annotations
from .server_configuration import JsonDict, Configuration
from typing import cast
import json
from logging import error


class ServerState(object):
    """
    Current state of the server
    """
    def __init__(
            self,
            configuration: Configuration,
            next_contributor_index: int,
            num_contributors: int,
            next_contributor_deadline: float):
        assert num_contributors != 0
        self.configuration = configuration
        self.next_contributor_index: int = next_contributor_index
        self.num_contributors: int = num_contributors
        self.next_contributor_deadline: float = next_contributor_deadline

    @staticmethod
    def new(configuration: Configuration) -> ServerState:
        assert configuration.start_time != 0.0
        assert configuration.contribution_interval != 0.0
        state = ServerState(
            configuration,
            0,
            len(configuration.contributors),
            configuration.start_time + configuration.contribution_interval)
        state._notify_next_contributor()
        return state

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    @staticmethod
    def from_json(configuration: Configuration, state_json: str) -> ServerState:
        return ServerState._from_json_dict(configuration, json.loads(state_json))

    def have_all_contributions(self) -> bool:
        """
        returns True if all contributions have been received
        """
        return self.num_contributors <= self.next_contributor_index

    def received_contribution(self, now: float) -> None:
        """
        Update the state after new contribution has been successfully received.
        """
        assert not self.have_all_contributions()
        self._next_contributor(now)

    def update(self, now: float) -> bool:
        """
        Check whether a contributor has missed his chance.  If the next deadline
        has not passed, do nothing and return False.  If the deadline has
        passed, update and contact the next participant.
        """
        # If the next contributor deadline has passed, update
        if now < self.next_contributor_deadline:
            return False

        self._next_contributor(now)
        return True

    def _next_contributor(self, now: float) -> None:

        self.next_contributor_index = self.next_contributor_index + 1
        self._update_deadline(now)
        self._notify_next_contributor()

    def _notify_next_contributor(self) -> None:
        from .crypto import export_verification_key

        if self.have_all_contributions() or not self.configuration.email_server:
            return

        contr = self.configuration.contributors[self.next_contributor_index]
        contr_idx = self.next_contributor_index + 1
        total = self.num_contributors
        try:
            _send_mail(
                email_server=self.configuration.email_server,
                email_address=cast(str, self.configuration.email_address),
                email_password=cast(str, self.configuration.email_password),
                to=contr.email,
                subject=f"[MPC] Your timeslot has begun ({contr_idx}/{total})",
                body="Please contribute to the MPC using your key: " +
                export_verification_key(contr.verification_key))
        except Exception as ex:
            error(f"Failed to notify: {contr.email}: {ex}")

    def _to_json_dict(self) -> JsonDict:
        return {
            "next_contributor_index": self.next_contributor_index,
            "num_contributors": self.num_contributors,
            "next_contributor_deadline": str(self.next_contributor_deadline),
        }

    @staticmethod
    def _from_json_dict(
            configuration: Configuration, json_dict: JsonDict) -> ServerState:
        return ServerState(
            configuration,
            cast(int, json_dict["next_contributor_index"]),
            cast(int, json_dict["num_contributors"]),
            float(cast(str, json_dict["next_contributor_deadline"])))

    def _update_deadline(self, now: float) -> None:
        if self.have_all_contributions():
            self.next_contributor_deadline = 0.0
        else:
            self.next_contributor_deadline = \
                now + self.configuration.contribution_interval


def _send_mail(
        email_server: str,
        email_address: str,
        email_password: str,
        to: str,
        subject: str,
        body: str) -> None:
    """
    Send an email, given a server + credentials
    """
    from ssl import create_default_context
    from smtplib import SMTP_SSL
    from email.message import EmailMessage

    host_port = email_server.split(":")
    host = host_port[0]
    if len(host_port) == 2:
        port = int(host_port[1])
    else:
        port = 465

    ssl_ctx = create_default_context()
    with SMTP_SSL(host, port, context=ssl_ctx) as smtp:
        smtp.login(email_address, email_password)
        msg = EmailMessage()
        msg.set_content(f"Subject: {subject}\n\n{body}")
        msg['Subject'] = subject
        msg['From'] = email_address
        msg['To'] = to
        smtp.send_message(msg)
        # server.sendmail(email_address, to, body)
