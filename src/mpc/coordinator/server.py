#!/usr/bin/env python3

"""
server command
"""

from cheroot.wsgi import Server as WSGIServer, PathInfoDispatcher  # type: ignore
from coordinator.icontributionhandler import IContributionHandler
from coordinator.interval import Interval
from coordinator.server_state import Configuration, ServerState
from coordinator.upload_utils import handle_upload_request
from coordinator.crypto import \
    import_digest, export_verification_key, import_signature, verify
from typing import cast, Optional, Callable
from flask import Flask, request, Request, Response
from threading import Thread, Lock
import io
import time
import logging
from logging import info, warning
from os import remove
from os.path import exists, join

CONFIGURATION_FILE = "server_config.json"
STATE_FILE = "server_state.json"
UPLOAD_FILE = "upload.raw"
LOG_FILE = "server.log"


class Server(object):
    """
    Server to coordinate an MPC, that serves challenges and accepts responses
    from contributors.  Performs basic contribution management, ensuring
    contributions are from the correct party, contributed within the correct
    interval.  MPC-specific operations (validation / challenge computation,
    etc) is performed by an IContributionHandler object.
    """

    def __init__(
            self,
            handler: IContributionHandler,
            server_dir: str):

        logging.basicConfig(filename="server.log", level=logging.DEBUG)
        self.handler = handler
        self.config: Configuration
        self.upload_file = join(server_dir, UPLOAD_FILE)
        self.state_file_path = join(server_dir, STATE_FILE)
        self.state: ServerState

        # Try to open config file and state files
        config_file_name = join(server_dir, CONFIGURATION_FILE)
        with open(config_file_name, "r") as config_f:
            self.config = Configuration.from_json(config_f.read())

        if exists(STATE_FILE):
            info(f"run_server: using existing state file: {STATE_FILE}")
            with open(STATE_FILE, "r") as state_f:
                self.state = ServerState.from_json(state_f.read())
        else:
            self.state = ServerState.new(self.config)
            self._write_state_file()

        self.handler_finalized = self.state.have_all_contributions()
        self.state_lock = Lock()
        self.server: Optional[WSGIServer] = None
        self.thread = Thread(target=self._run)
        self.thread.start()

        while self.server is None or self.server.socket is None:
            info("Waiting for MPC server to start ...")
            time.sleep(1)
        port = self.server.socket.getsockname()[1]
        info(f"MPC server started (port: {port}).")

    def stop(self) -> None:
        if self.server is not None:
            self.server.stop()
            while self.server is not None:
                info("Waiting for server to stop ...")
                time.sleep(1.0)
            self.thread.join()
            info("Server stopped.")

    def _write_state_file(self) -> None:
        info(f"WRITING STATE: {self.state_file_path}")
        with open(self.state_file_path, "w") as state_f:
            state_f.write(self.state.to_json())

    def _finalize_handler_once(self) -> None:
        if (not self.handler_finalized) and self.state.have_all_contributions():
            self.handler_finalized = True
            self.handler.on_completed()

    def _update_state(self, now: float) -> None:
        if self.state.update(self.config, now):
            self._finalize_handler_once()
            self._write_state_file()

    def _on_contribution(self, now: float) -> None:
        self.state.received_contribution(self.config, now)
        self._finalize_handler_once()
        self._write_state_file()

    def _tick(self) -> None:
        self.state_lock.acquire()
        try:
            self._update_state(time.time())
        finally:
            self.state_lock.release()

    def _state(self, _req: Request) -> Response:
        from json import dumps as json_dumps
        return Response(json_dumps({
            "config": self.config._to_json_dict(),
            "state": self.state._to_json_dict(),
            }), 200)

    def _challenge(self, _req: Request) -> Response:
        self._update_state(time.time())
        if self.state.have_all_contributions():
            return Response(
                "MPC is complete.  No remaining challenges", 405)

        challenge_file = self.handler.get_current_challenge_file(
            self.state.next_contributor_index)
        return Response(
            open(challenge_file, "rb"),
            mimetype="application/octet-stream")

    def _contribute(self, request: Request) -> Response:
        try:
            # Basic request check
            headers = request.headers
            # print(f"contribute: headers = {headers}")
            if 'Content-Length' not in headers:
                raise Exception("no Content-Length header")
            if 'Content-Type' not in headers:
                raise Exception("no Content-Type header")
            if 'X-MPC-Digest' not in headers:
                raise Exception("no X-MPC-Digest header")
            if 'X-MPC-Public-Key' not in headers:
                raise Exception("no X-MPC-Public-Key header")
            if 'X-MPC-Signature' not in headers:
                raise Exception("no X-MPC-Signature header")

            content_length = int(headers['Content-Length'])
            content_type = headers['Content-Type']
            digest = import_digest(headers['X-MPC-Digest'])
            pub_key_str = headers.get('X-MPC-Public-Key')
            sig = import_signature(headers['X-MPC-Signature'])
            # print(f"contribute: content_length = {content_length}")
            # print(f"contribute: pub_key_str = {pub_key_str}")
            # print(f"contribute: sig = {export_signature(sig)}")
            # print(f"contribute: content_type = {content_type}")

            boundary: str = ""
            for val in content_type.split("; "):
                if val.startswith("boundary="):
                    boundary = val[len("boundary="):]
                    break
            if not boundary:
                raise Exception("content-type contains no boundary")

            now = time.time()
            info(f"contribute: current time = {now}")

            # Update state using the current time and return an error if
            # the MPC is no longer active.
            self._update_state(now)
            if self.state.have_all_contributions():
                return Response("MPC complete.  No contributions accepted.", 405)

            # Check that the public key matches the expected next
            # contributor (as text, rather than relying on comparison
            # operators)
            contributor_idx = self.state.next_contributor_index
            contributor = self.config.contributors[contributor_idx]
            pub_key = contributor.public_key
            expect_pub_key_str = export_verification_key(pub_key)
            if expect_pub_key_str != pub_key_str:
                return Response("contributor key mismatch", 403)

            # Check signature correctness.  Ensures that the uploader is
            # the owner of the correct key BEFORE the costly file upload.
            # Gives limited protection against DoS attacks (intentional or
            # otherwise) from people other than the next contributor.
            # (Note that this pre-upload check requires the digest to be
            # passed in the HTTP header.)
            if not verify(sig, pub_key, digest):
                return Response("signature check failed", 403)

            # Accept the upload (if the digest matches).  If successful,
            # pass the file to the handler.
            if exists(self.upload_file):
                remove(self.upload_file)
            handle_upload_request(
                content_length,
                boundary,
                digest,
                cast(io.BufferedIOBase, request.stream),
                self.upload_file)

            if not self.handler.process_contribution(
                    self.state.next_contributor_index,
                    UPLOAD_FILE):
                raise Exception("contribution failed")

            now = time.time()
            self._on_contribution(now)
            info(
                f"contribute: SUCCESS ({self.state.next_contributor_index}" +
                f"/{self.state.num_contributors} contribs), finished time " +
                f"= {now}")
            return Response("OK", 200)

        finally:
            # Remove the uploaded file if it is still there
            if exists(UPLOAD_FILE):
                remove(UPLOAD_FILE)

    def _run(self) -> None:
        # Server and end points
        app = Flask(__name__)

        def _with_state_lock(
                req: Request,
                cb: Callable[[Request], Response]) -> Response:
            self.state_lock.acquire()
            try:
                return cb(req)
            except Exception as ex:
                warning(f"error in request: {ex}")
                print(f"error in request: {ex}")
                return Response("error: {ex}", 400)
            finally:
                self.state_lock.release()

        @app.route('/state', methods=['GET'])
        def state() -> Response:
            return _with_state_lock(request, self._state)

        @app.route('/challenge', methods=['GET'])
        def challenge() -> Response:
            return _with_state_lock(request, self._challenge)

        @app.route('/contribute', methods=['POST'])
        def contribute() -> Response:
            return _with_state_lock(request, self._contribute)

        def _tick() -> None:
            self.state_lock.acquire()
            try:
                self._update_state(time.time())
            finally:
                self.state_lock.release()

        interval = Interval(60.0, _tick)
        try:
            self.server = WSGIServer(
                ('0.0.0.0', self.config.port),
                PathInfoDispatcher({'/': app}),
                numthreads=1)
            self.server.start()
        finally:
            # print("(thread) Stopping ...", end='')
            interval.stop()
            self.server = None
            # print("(thread) DONE")
