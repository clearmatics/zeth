# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
import time
from typing import Optional


class Timer:
    """
    Very simple class to help measure time.
    """

    def __init__(self) -> None:
        self._start_time: Optional[float] = None

    def start(self) -> None:
        assert self._start_time is None
        self._start_time = time.time()

    @staticmethod
    def started() -> Timer:
        timer = Timer()
        timer.start()
        return timer

    def elapsed_seconds(self) -> float:
        assert self._start_time is not None
        return time.time() - self._start_time
