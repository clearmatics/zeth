#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import time
from threading import Condition, Thread
from typing import Callable


class Interval:
    """
    Simple thread that periodically executes a callback (in a thread).
    """
    def __init__(self, period: float, callback: Callable[[], None]):
        self.period = period
        self.callback = callback
        self.next_deadline = time.time()
        self.running = True
        self.condition = Condition()
        self.thread = Thread(target=self._thread)
        self.thread.start()

    def stop(self) -> None:
        self.running = False
        self.condition.acquire()
        self.condition.notify()
        self.condition.release()
        self.thread.join()

    def _thread(self) -> None:
        while self.running:
            self.callback()
            self.next_deadline = self.next_deadline + self.period

            self.condition.acquire()
            while self.running:
                now = time.time()
                if now >= self.next_deadline:
                    break
                self.condition.wait(self.next_deadline - now)
