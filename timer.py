import asyncio
from inspect import iscoroutine

import logging_config

logger = logging_config.init_logging()

class Timer:
    def __init__(self, timeout: float, repeating: bool, callback, callback_args = (), callback_kwargs = {}):
        self._timeout = timeout
        self._callback = callback
        if repeating:
            self._task = asyncio.create_task(self._periodic())
        else:
            self._task = asyncio.create_task(self._job())
        self._callback_args = callback_args
        self._callback_kwargs = callback_kwargs

    async def _periodic(self):
        while True:
            await asyncio.sleep(self._timeout)
            await self._call_callback()

    async def _job(self):
        await asyncio.sleep(self._timeout)
        await self._call_callback()

    async def _call_callback(self):
        if asyncio.iscoroutine(self._callback):
            await self._callback(*self._callback_args, **self._callback_kwargs)
        else:
            self._callback(*self._callback_args, **self._callback_kwargs)

    def cancel(self):
        self._task.cancel()

    def end_early(self):
        self._task.cancel()
        asyncio.create_task(self._call_callback())
