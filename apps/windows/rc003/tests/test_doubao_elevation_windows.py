import sys
import unittest
from unittest import mock

from ovb_rc003 import doubao_elevation_windows as elevation


class DoubaoElevationPureTests(unittest.TestCase):
    def test_frozen_helper_command_reuses_packaged_executable(self):
        command = elevation.build_helper_command(
            r"C:\Apps\RemoteMicRC003.exe",
            frozen=True,
            parent_pid=1234,
            nonce="a" * 32,
            vk_codes=(0xA2, 0x5B),
        )
        self.assertEqual(
            command,
            [
                r"C:\Apps\RemoteMicRC003.exe",
                elevation.HELPER_FLAG,
                "1234",
                "a" * 32,
                "A2,5B",
            ],
        )

    def test_source_helper_command_uses_module_entrypoint(self):
        command = elevation.build_helper_command(
            r"C:\venv\python.exe",
            frozen=False,
            parent_pid=9,
            nonce="b" * 32,
            vk_codes=(0xA5,),
        )
        self.assertEqual(
            command[:4],
            [r"C:\venv\python.exe", "-m", "ovb_rc003", elevation.HELPER_FLAG],
        )
        self.assertEqual(
            elevation.parse_helper_args(command[-3:]), (9, "b" * 32, (0xA5,))
        )

    def test_helper_parser_rejects_unbounded_or_malformed_keys(self):
        invalid = (
            ["1", "a" * 32, ""],
            ["1", "a" * 32, "GG"],
            ["1", "a" * 32, "00"],
            ["1", "a" * 32, "01,02,03,04,05,06,07,08,09"],
            ["0", "a" * 32, "A5"],
            ["1", "short", "A5"],
        )
        for args in invalid:
            with self.subTest(args=args), self.assertRaises(ValueError):
                elevation.parse_helper_args(args)

    def test_event_names_are_random_launch_scoped_and_local_session_only(self):
        ready, failed = elevation._event_names(4321, "c" * 32)
        self.assertTrue(ready.startswith(r"Local\RemoteMicRC003_Doubao_4321_"))
        self.assertTrue(ready.endswith("_ready"))
        self.assertTrue(failed.endswith("_failed"))


class DoubaoElevationLaunchTests(unittest.TestCase):
    def setUp(self):
        elevation._helper_process_handle = None
        elevation._helper_vk_codes = None
        elevation._last_error = None

    def tearDown(self):
        elevation._helper_process_handle = None
        elevation._helper_vk_codes = None
        elevation._last_error = None

    def test_ready_helper_is_retained_and_reused_without_second_uac(self):
        with mock.patch.object(
            elevation, "_helper_is_alive", side_effect=[False, True]
        ), mock.patch.object(
            elevation, "_create_event", side_effect=[11, 12]
        ), mock.patch.object(
            elevation, "_shell_execute_elevated", return_value=(13, 777)
        ) as launch, mock.patch.object(
            elevation, "_wait_for_launch_result", return_value="ready"
        ), mock.patch.object(
            elevation, "_close_handle"
        ) as close, mock.patch.object(
            elevation.os, "getpid", return_value=222
        ), mock.patch.object(
            elevation.uuid, "uuid4", return_value=mock.Mock(hex="d" * 32)
        ), mock.patch.object(
            elevation.sys, "executable", r"C:\Apps\RemoteMicRC003.exe"
        ), mock.patch.object(
            elevation.sys, "frozen", True, create=True
        ):
            self.assertTrue(elevation.ensure_elevated_physicalizer((0xA2, 0x5B)))
            self.assertTrue(elevation.ensure_elevated_physicalizer((0xA2, 0x5B)))

        self.assertEqual(launch.call_count, 1)
        self.assertEqual(elevation._helper_process_handle, 13)
        self.assertEqual(elevation._helper_vk_codes, (0xA2, 0x5B))
        self.assertIn(mock.call(11), close.mock_calls)
        self.assertIn(mock.call(12), close.mock_calls)
        self.assertNotIn(mock.call(13), close.mock_calls)

    def test_failed_helper_closes_every_handle_and_reports_reason(self):
        with mock.patch.object(
            elevation, "_helper_is_alive", return_value=False
        ), mock.patch.object(
            elevation, "_create_event", side_effect=[21, 22]
        ), mock.patch.object(
            elevation, "_shell_execute_elevated", return_value=(23, 888)
        ), mock.patch.object(
            elevation, "_wait_for_launch_result", return_value="failed"
        ), mock.patch.object(
            elevation, "_close_handle"
        ) as close, mock.patch.object(
            elevation.os, "getpid", return_value=333
        ), mock.patch.object(
            elevation.uuid, "uuid4", return_value=mock.Mock(hex="e" * 32)
        ), mock.patch.object(
            elevation.sys, "executable", sys.executable
        ):
            self.assertFalse(elevation.ensure_elevated_physicalizer((0xA5,)))

        self.assertIn("rejected", elevation.elevation_error() or "")
        self.assertIn(mock.call(21), close.mock_calls)
        self.assertIn(mock.call(22), close.mock_calls)
        self.assertIn(mock.call(23), close.mock_calls)
        self.assertIsNone(elevation._helper_process_handle)


if __name__ == "__main__":
    unittest.main()
