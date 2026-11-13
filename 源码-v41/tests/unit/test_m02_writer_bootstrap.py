import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "bootstrap_m02_writer.py"
spec = importlib.util.spec_from_file_location("bootstrap_m02_writer", SCRIPT)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class PasswordHandlingTests(unittest.TestCase):
    def test_random_password_row_parser(self):
        out = (
            "M02_SESSION_OFF|0|1|OFF\n"
            "orderguard_m02_writer\tlocalhost\tA!b#C\\d\"E\t1\n"
            "M02_SESSION_RESTORED|1|1|OFF\n"
        )
        self.assertEqual(
            module.parse_random_password(out),
            'A!b#C\\d"E'
        )

    def test_password_is_not_accepted_with_control_characters(self):
        out = "orderguard_m02_writer\tlocalhost\tbad\npass\t1\n"
        self.assertIsNone(module.parse_random_password(out))

    def test_option_file_escaping(self):
        value = 'A!b#C\\d"E'
        encoded = module.option_quote(value)
        self.assertEqual(encoded, '"A!b#C\\\\d\\"E"')

    def test_session_markers_require_both_states(self):
        good = (
            "M02_SESSION_OFF|0|1|OFF\n"
            "M02_SESSION_RESTORED|1|1|OFF\n"
        )
        module.validate_session_markers(good)
        with self.assertRaises(module.SafeError):
            module.validate_session_markers("M02_SESSION_OFF|0|1|OFF\n")

    def test_sql_never_contains_a_password_literal(self):
        sql = module.create_sql()
        self.assertIn("IDENTIFIED BY RANDOM PASSWORD", sql)
        self.assertNotIn("password=", sql.lower())
        self.assertNotIn("SET GLOBAL log_bin", sql)
        self.assertIn("SET SESSION sql_log_bin = OFF", sql)
        self.assertIn("SET SESSION sql_log_bin = ON", sql)


if __name__ == "__main__":
    unittest.main()
