import math
import hashlib
import os
from pathlib import Path
import random
import struct
import sys
import tempfile
import unittest

from ciberfox.energy import EnergyManager, PowerSample, illustrative_teg, summarize
from ciberfox.detector import Detector, Event
from ciberfox.demo import simulate, write_fixture, checksum
from ciberfox.tshark_adapter import validate_pcap, parse_row, check_version, command, decode
from ciberfox.__main__ import replay_power


class EnergyTests(unittest.TestCase):
    def test_no_temperature_gradient_no_generation(self):
        self.assertEqual(illustrative_teg(30, 30)["harvest_dc_w"], 0)
        self.assertEqual(illustrative_teg(20, 30)["harvest_dc_w"], 0)

    def test_generation_below_carnot(self):
        for temperature in (31, 40, 60, 90):
            result = illustrative_teg(temperature, 30)
            self.assertLessEqual(result["teg_gross_w"], result["q_hot_assumed_w"] * result["carnot_upper_bound"])

    def test_conservation_random_trace(self):
        rng = random.Random(21)
        manager = EnergyManager()
        for _ in range(1000):
            before = manager.stored
            result = manager.step(PowerSample(rng.uniform(0, 10), 60, 30), rng.uniform(.01, 5))
            self.assertAlmostEqual(result.load_wh, result.recovered_to_load_wh + result.grid_dc_wh)
            self.assertAlmostEqual(before + result.harvest_accepted_wh + result.grid_dc_wh,
                                   result.load_wh + result.stored_wh + result.curtailed_wh + result.storage_loss_wh)
            self.assertGreaterEqual(manager.stored, -1e-12)
            self.assertLessEqual(manager.stored, manager.capacity + 1e-12)

    def test_no_harvest_does_not_disable_detection_load(self):
        result = EnergyManager().step(PowerSample(0, 30, 30), 60)
        self.assertEqual(result.mode, "CORE_ONLY")
        self.assertAlmostEqual(result.grid_dc_wh, 3 / 60)
        self.assertEqual(result.recovered_to_load_wh, 0)

    def test_thermal_fault_keeps_backup(self):
        result = EnergyManager().step(PowerSample(20, 80, 30), 1)
        self.assertEqual(result.warning, "THERMAL_REVIEW_REQUIRED")
        self.assertEqual(result.harvest_accepted_wh, 0)
        self.assertEqual(result.grid_dc_wh, result.load_wh)

    def test_stale_telemetry_cannot_claim_generation(self):
        result = EnergyManager().step(PowerSample(20, 60, 30, age_s=6))
        self.assertEqual(result.warning, "STALE_POWER_TELEMETRY")
        self.assertEqual(result.harvest_accepted_wh, 0)

    def test_nan_inf_and_negative_rejected(self):
        for value in (math.nan, math.inf, -1):
            with self.assertRaises(ValueError):
                EnergyManager().step(PowerSample(value, 60, 30))

    def test_cooling_can_erase_benefit(self):
        result = EnergyManager().step(PowerSample(0.1, 60, 30, extra_cooling_w=1), 60)
        self.assertLess(summarize([result])["grid_saving_vs_same_load_wh"], 0)

    def test_optional_work_only_after_buffer_charge(self):
        manager = EnergyManager()
        self.assertEqual(manager.step(PowerSample(10, 60, 30)).mode, "CORE_ONLY")
        for _ in range(150):
            last = manager.step(PowerSample(10, 60, 30))
        self.assertEqual(last.mode, "CORE_PLUS_REPORTS")
        self.assertEqual(manager.step(PowerSample(0, 30, 30)).mode, "CORE_ONLY")


class DetectionTests(unittest.TestCase):
    def test_authorized_and_boundary_values(self):
        detector = Detector()
        for value in (20, 40, 60):
            self.assertEqual(detector.inspect(Event(1, "192.0.2.10", "192.0.2.20", 1, 6, 100, value)), [])

    def test_authorized_source_does_not_bypass_process_limit(self):
        alerts = Detector().inspect(Event(1, "192.0.2.10", "192.0.2.20", 1, 6, 100, 90))
        self.assertEqual(alerts[0]["code"], "PROCESS_LIMIT")

    def test_untrusted_source_and_unknown_register(self):
        alerts = Detector().inspect(Event(1, "192.0.2.99", "192.0.2.20", 1, 6, 200, 40))
        self.assertEqual({a["code"] for a in alerts}, {"UNAUTHORIZED_COMMAND", "UNAPPROVED_REGISTER"})

    def test_unsupported_write_is_not_silent(self):
        alerts = Detector().inspect(Event(1, "192.0.2.10", "192.0.2.20", 1, 16))
        self.assertEqual(alerts[0]["code"], "UNSUPPORTED_CONTROL")

    def test_same_alerts_under_different_energy_budgets(self):
        small, large = simulate(4), simulate(32)
        self.assertEqual(small["alerts"], large["alerts"])
        self.assertEqual(small["events_inspected"], 20)
        self.assertEqual(len(small["alerts"]), 3)
        self.assertGreater(small["balance"]["grid_increment_vs_no_monitor_wh"], 0)


class AdapterTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix" and os.geteuid() != 0, "POSIX no root")
    def test_subprocess_pipeline_with_explicit_test_double(self):
        # Exercises orchestration, NOT genuine Wireshark dissection.
        with tempfile.TemporaryDirectory() as folder:
            binary, pcap = Path(folder) / "fake_tshark", Path(folder) / "fixture.pcap"
            binary.write_text("#!" + sys.executable + "\nimport sys\n"
                              "if '--version' in sys.argv:\n print('TShark (Wireshark) 4.6.9')\n"
                              "else:\n print('1\\t192.0.2.99\\t192.0.2.20\\t1\\t6\\t100\\t50')\n")
            binary.chmod(0o500)
            write_fixture(pcap)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            events, health = decode(pcap, binary, digest)
            self.assertEqual(health["status"], "SCOPED_ANALYSIS")
            self.assertEqual(Detector().inspect(events[0])[0]["code"], "UNAUTHORIZED_COMMAND")
            with self.assertRaises(ValueError):
                decode(pcap, binary, "0" * 64)

    def test_documented_fields_and_no_shell(self):
        args = command("/opt/tshark", "/tmp/demo.pcap")
        self.assertIn("modbus.regval_uint16", args)
        self.assertIn("--only-protocols", args)
        self.assertNotIn("modbus.reg16", args)
        self.assertNotIn("-i", args)
        self.assertNotIn("-V", args)

    def test_version_gate(self):
        self.assertEqual(check_version("TShark (Wireshark) 4.6.9 (build)"), "4.6.9")
        for version in ("4.6.8", "4.7.0", "4.6.9rc1", "4.6.9-rc1", "4.4.0"):
            with self.assertRaises(ValueError):
                check_version("TShark (Wireshark) " + version)

    def test_reject_multi_pdu_missing_and_nonfinite(self):
        for line in ("1\t192.0.2.10\t192.0.2.20\t1\t6,6\t100\t40",
                     "nan\t192.0.2.10\t192.0.2.20\t1\t6\t100\t40",
                     "1\t192.0.2.10\t192.0.2.20\t1\t6\t100\t"):
            with self.assertRaises(ValueError):
                parse_row(line)

    def test_parse_single_request(self):
        event = parse_row("1.5\t192.0.2.10\t192.0.2.20\t1\t6\t100\t40\n")
        self.assertEqual(event.value, 40)

    def test_fixture_valid_and_truncation_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.pcap"
            write_fixture(path)
            self.assertEqual(validate_pcap(path), 16)
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaises(ValueError):
                validate_pcap(path)

    def test_fixture_ip_and_tcp_checksums(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.pcap"
            write_fixture(path)
            with path.open("rb") as stream:
                stream.read(24)
                while record := stream.read(16):
                    included = struct.unpack("<IIII", record)[2]
                    frame = stream.read(included)
                    ip, tcp = frame[14:34], frame[34:]
                    self.assertEqual(checksum(ip), 0)
                    pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
                    self.assertEqual(checksum(pseudo + tcp), 0)

    def test_power_csv_gap_invalidates_accounting(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "power.csv"
            header = "timestamp_s,harvest_dc_w,hot_c,cold_c,extra_cooling_w\n"
            path.write_text(header + "0,1,60,30,0.1\n1,1,60,30,0.1\n")
            self.assertIn("balance", replay_power(path))
            path.write_text(header + "0,1,60,30,0.1\n10,1,60,30,0.1\n")
            with self.assertRaises(ValueError):
                replay_power(path)


if __name__ == "__main__":
    unittest.main()
