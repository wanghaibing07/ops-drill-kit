import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import unittest
from unittest.mock import MagicMock, patch

import install_n04 as installer
import n04
import n04_lifecycle as life


class InstallTests(unittest.TestCase):
    def setUp(self):
        for name in ('O_NOFOLLOW', 'O_NONBLOCK', 'O_CLOEXEC', 'O_DIRECTORY'):
            if not hasattr(os, name):
                item = patch.object(os, name, 0, create=True)
                item.start()
                self.addCleanup(item.stop)

    def test_manifest_matches_exact_file_bytes(self):
        root = Path(__file__).resolve().parent
        self.assertEqual(set(installer.MANIFEST), {'n04.py', 'n04_lifecycle.py'})
        for name, digest in installer.MANIFEST.items():
            self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest, name)

    def test_all_guards_reject_unsafe_marker_and_non_vmware(self):
        marker = MagicMock(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1, st_size=13)
        for module in (installer, n04, life):
            with self.subTest(module=module.__name__), \
                 patch.object(module.os, 'geteuid', return_value=0, create=True), \
                 patch.object(module.os, 'open', return_value=31), patch.object(module.os, 'close'), \
                 patch.object(module.os, 'fstat', return_value=marker), \
                 patch.object(module.os, 'read', return_value=b'wrong'), \
                 patch.object(module.subprocess, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'marker'):
                    module.guard()
                run.assert_not_called()
            with self.subTest(module=module.__name__, failure='virt'), \
                 patch.object(module.os, 'geteuid', return_value=0, create=True), \
                 patch.object(module.os, 'open', return_value=31), patch.object(module.os, 'close'), \
                 patch.object(module.os, 'fstat', return_value=marker), \
                 patch.object(module.os, 'read', return_value=b'ops-drill-kit'), \
                 patch.object(module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'kvm\n', '')):
                with self.assertRaisesRegex(RuntimeError, 'VMware'):
                    module.guard()

    def test_guard_rejects_nonroot_before_access(self):
        for module in (installer, n04, life):
            with self.subTest(module=module.__name__), \
                 patch.object(module.os, 'geteuid', return_value=1000, create=True), \
                 patch.object(module.os, 'open') as opened:
                with self.assertRaisesRegex(RuntimeError, 'root'):
                    module.guard()
                opened.assert_not_called()

    def test_guard_accepts_only_safe_marker_in_vmware(self):
        marker = MagicMock(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1, st_size=13)
        for module in (installer, n04, life):
            with self.subTest(module=module.__name__), \
                 patch.object(module.os, 'geteuid', return_value=0, create=True), \
                 patch.object(module.os, 'open', return_value=31), patch.object(module.os, 'close'), \
                 patch.object(module.os, 'fstat', return_value=marker), \
                 patch.object(module.os, 'read', return_value=b'ops-drill-kit'), \
                 patch.object(module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'vmware\n', '')):
                module.guard()
        marker.st_mode = stat.S_IFREG | 0o666
        with patch.object(life.os, 'geteuid', return_value=0, create=True), \
             patch.object(life.os, 'open', return_value=31), patch.object(life.os, 'close'), \
             patch.object(life.os, 'fstat', return_value=marker), patch.object(life.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'marker'):
                life.guard()
            run.assert_not_called()

    def test_runtime_rejects_installed_manifest_digest_mismatch(self):
        source = b'candidate'
        digest = hashlib.sha256(source).hexdigest()
        manifest = json.dumps({'n04.py': digest, 'n04_lifecycle.py': 'f' * 64}).encode()
        stream = MagicMock()
        stream.__enter__.return_value.read.return_value = source
        file_stat = MagicMock(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1, st_size=len(source))
        manifest_stat = MagicMock(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1, st_size=len(manifest))
        with patch.object(life, '__file__', '/trusted/n04_lifecycle.py'), \
             patch.object(life, 'INSTALL', Path('/trusted').absolute()), patch.object(life, 'secure_dir'), \
             patch.object(life.os, 'open', side_effect=[10, 11, 12]), \
             patch.object(life.os, 'fstat', side_effect=[file_stat, file_stat, manifest_stat]), \
             patch.object(life.os, 'fdopen', return_value=stream), patch.object(life.os, 'read', return_value=manifest), \
             patch.object(life.os, 'close'):
            with self.assertRaisesRegex(RuntimeError, 'digest mismatch'):
                life.protected_sources()

    def test_installer_refuses_different_existing_file_before_link(self):
        root = Path(__file__).resolve().parent
        files = {name: (root / name).read_bytes() for name in installer.MANIFEST}
        files['manifest.json'] = (json.dumps(installer.MANIFEST, sort_keys=True) + '\n').encode('ascii')
        directory = MagicMock(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        with patch.object(installer.os, 'open', side_effect=range(10, 17)), \
             patch.object(installer.os, 'mkdir'), patch.object(installer.os, 'fstat', return_value=directory), \
             patch.object(installer.os, 'close'), patch.object(installer.os, 'listdir', return_value=['n04.py']), \
             patch.object(installer, 'secure_file', return_value=b'foreign'), \
             patch.object(installer.os, 'link') as link:
            with self.assertRaisesRegex(RuntimeError, 'existing file differs'):
                installer.install(files)
        link.assert_not_called()


if __name__ == '__main__':
    unittest.main()
