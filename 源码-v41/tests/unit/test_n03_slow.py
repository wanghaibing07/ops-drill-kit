import asyncio
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

source = Path(__file__).with_name('n03_slow.py')
if not source.exists():
    source = Path(__file__).resolve().parents[2] / 'app/n03_slow.py'
spec = importlib.util.spec_from_file_location('n03_slow_test', source)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class SlowEndpointTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        m._inflight = False

    async def test_disabled_by_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(HTTPException) as error:
                await m.slow_orders()
            self.assertEqual(error.exception.status_code, 404)

    async def test_fixed_delay_and_success(self):
        with mock.patch.dict(os.environ, {'OPSDRILL_ENABLE_SLOW': '1'}), \
             mock.patch.object(m, 'gate_active', return_value=True), \
             mock.patch.object(m.asyncio, 'sleep', new_callable=mock.AsyncMock) as sleep:
            self.assertEqual(await m.slow_orders(), {'status': 'slow drill completed'})
            sleep.assert_awaited_once_with(12)
            self.assertFalse(m._inflight)

    async def test_one_request_at_a_time_and_cancel_releases_slot(self):
        entered = asyncio.Event()
        release = asyncio.Event()
        async def blocked(_seconds):
            entered.set()
            await release.wait()
        with mock.patch.dict(os.environ, {'OPSDRILL_ENABLE_SLOW': '1'}), \
             mock.patch.object(m, 'gate_active', return_value=True), \
             mock.patch.object(m.asyncio, 'sleep', side_effect=blocked):
            task = asyncio.create_task(m.slow_orders())
            await entered.wait()
            with self.assertRaises(HTTPException) as error:
                await m.slow_orders()
            self.assertEqual(error.exception.status_code, 429)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertFalse(m._inflight)

    async def test_enabled_without_gate_is_still_unavailable(self):
        with mock.patch.dict(os.environ, {'OPSDRILL_ENABLE_SLOW': '1'}), \
             mock.patch.object(m, 'gate_active', return_value=False):
            with self.assertRaises(HTTPException) as error:
                await m.slow_orders()
            self.assertEqual(error.exception.status_code, 404)

    async def test_gate_rejects_bad_content_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate = root / 'gate'
            gate.mkdir(mode=0o755)
            boot_id = root / 'boot-id'
            boot = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            boot_id.write_text(boot, encoding='ascii')
            trigger = gate / 'slow.trigger'
            payload = ('opsdrill-n03-504:%s:%s:%d:%d\n' % ('a' * 24, boot, 100, 1000)).encode('ascii')
            with mock.patch.object(m, 'GATE_DIR', gate), mock.patch.object(m, 'BOOT_ID', boot_id), \
                 mock.patch.object(m, 'ROOT_UID', os.geteuid()), mock.patch.object(m.time, 'monotonic_ns', return_value=200):
                self.assertFalse(m.gate_active())
                trigger.write_bytes(payload)
                trigger.chmod(0o644)
                self.assertTrue(m.gate_active())
                trigger.write_bytes(payload + b'x')
                with mock.patch.object(m.os, 'read', return_value=payload):
                    self.assertFalse(m.gate_active())
                trigger.write_bytes(payload)
                trigger.chmod(0o666)
                self.assertFalse(m.gate_active())
                trigger.chmod(0o644)
                trigger.write_bytes(b'wrong')
                self.assertFalse(m.gate_active())
                trigger.unlink()
                trigger.symlink_to('/etc/passwd')
                self.assertFalse(m.gate_active())

    async def test_gate_expires_without_watchdog_and_is_bound_to_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate = root / 'gate'
            gate.mkdir(mode=0o755)
            boot_id = root / 'boot-id'
            boot = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            boot_id.write_text(boot, encoding='ascii')
            trigger = gate / 'slow.trigger'
            def write(created, expires, gate_boot=boot):
                trigger.write_text('opsdrill-n03-504:%s:%s:%d:%d\n' %
                                   ('a' * 24, gate_boot, created, expires), encoding='ascii')
                trigger.chmod(0o644)
            with mock.patch.object(m, 'GATE_DIR', gate), mock.patch.object(m, 'BOOT_ID', boot_id), \
                 mock.patch.object(m, 'ROOT_UID', os.geteuid()), mock.patch.object(m.time, 'monotonic_ns', return_value=200):
                write(100, 201)
                self.assertTrue(m.gate_active())
                write(100, 200)
                self.assertFalse(m.gate_active())
                write(201, 300)
                self.assertFalse(m.gate_active())
                write(100, 100 + m.MAX_GATE_TTL_NS + 1)
                self.assertFalse(m.gate_active())
                write(100, 201, 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee')
                self.assertFalse(m.gate_active())


if __name__ == '__main__':
    unittest.main(verbosity=2)
