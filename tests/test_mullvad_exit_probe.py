#!/usr/bin/env python3
"""Tests for Mullvad SOCKS5 exit IP probe."""

import pytest
import sys
import os
import csv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from unittest.mock import patch, MagicMock
from mullvad_exit_probe import probe_relay, fetch_relays, write_results


class TestFetchRelays:
    SAMPLE_RELAYS = [
        {
            "hostname": "us-mkc-wg-001",
            "active": True,
            "ipv4_addr_in": "155.2.191.3",
            "socks_name": "us-mkc-wg-socks5-001.relays.mullvad.net",
            "socks_port": 1080,
            "type": "wireguard",
            "country_code": "us",
            "city_name": "Kansas City, MO",
        },
        {
            "hostname": "de-ber-br-001",
            "active": False,
            "ipv4_addr_in": "10.0.0.1",
            "socks_name": "de-ber-br-socks5-001.relays.mullvad.net",
            "socks_port": 1080,
            "type": "bridge",
            "country_code": "de",
            "city_name": "Berlin",
        },
    ]

    def test_fetches_active_relays_only(self):
        with patch("mullvad_exit_probe.requests") as mock_req:
            mock_resp = MagicMock()
            mock_resp.json.return_value = self.SAMPLE_RELAYS
            mock_resp.raise_for_status = MagicMock()
            mock_req.get.return_value = mock_resp
            relays = fetch_relays()
        assert len(relays) == 1
        assert relays[0]["hostname"] == "us-mkc-wg-001"

    def test_relay_has_socks_fields(self):
        with patch("mullvad_exit_probe.requests") as mock_req:
            mock_resp = MagicMock()
            mock_resp.json.return_value = self.SAMPLE_RELAYS
            mock_resp.raise_for_status = MagicMock()
            mock_req.get.return_value = mock_resp
            relays = fetch_relays()
        assert relays[0]["socks_name"] == "us-mkc-wg-socks5-001.relays.mullvad.net"
        assert relays[0]["socks_port"] == 1080


class TestProbeRelay:
    def test_probe_returns_exit_ip(self):
        relay = {
            "hostname": "us-mkc-wg-001",
            "ipv4_addr_in": "155.2.191.3",
            "socks_name": "us-mkc-wg-socks5-001.relays.mullvad.net",
            "socks_port": 1080,
        }
        with patch("mullvad_exit_probe.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"ip": "155.2.190.72"}
            mock_resp.raise_for_status = MagicMock()
            mock_get.return_value = mock_resp
            result = probe_relay(relay)
        assert result == "155.2.190.72"
        # Verify SOCKS5 proxy was used
        call_kwargs = mock_get.call_args[1]
        assert "socks5h://" in call_kwargs["proxies"]["http"]

    def test_probe_returns_none_on_failure(self):
        relay = {
            "hostname": "broken-001",
            "ipv4_addr_in": "10.0.0.1",
            "socks_name": "broken.relays.mullvad.net",
            "socks_port": 1080,
        }
        with patch("mullvad_exit_probe.requests.get", side_effect=Exception("timeout")):
            result = probe_relay(relay)
        assert result is None


class TestWriteResults:
    def test_writes_csv_with_correct_columns(self, tmp_path):
        results = [
            {"relay_hostname": "us-mkc-wg-001", "ingress_ip": "155.2.191.3",
             "exit_ip": "155.2.190.72", "probe_date": "2026-05-03"},
        ]
        out = tmp_path / "exit_ips.csv"
        write_results(results, str(out))

        with open(out) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["exit_ip"] == "155.2.190.72"
        assert set(reader.fieldnames) == {"relay_hostname", "ingress_ip", "exit_ip", "probe_date"}
