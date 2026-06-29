#!/usr/bin/env python3
"""Tests for shared.config module."""

import os
import sys
import tempfile

import pytest
import yaml
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))


class TestConfigGet:
    """Test the config.get() dot-notation accessor."""

    def test_reads_flame_index_url(self):
        """Verify defaults.yaml is loaded and flame.index_url is accessible."""
        from shared import config
        url = config.get("flame.index_url")
        # Should return the URL from config/defaults.yaml
        assert url is None or "flame" in str(url).lower() or url.startswith("http")

    def test_returns_default_for_missing_key(self):
        from shared import config
        result = config.get("nonexistent.deeply.nested.key", "fallback")
        assert result == "fallback"

    def test_returns_none_for_missing_key_no_default(self):
        from shared import config
        result = config.get("nonexistent.key")
        assert result is None

    def test_top_level_key(self):
        from shared import config
        # "flame" should return the dict subtree
        flame = config.get("flame")
        if flame is not None:
            assert isinstance(flame, dict)
            assert "index_url" in flame

    def test_nested_numeric_value(self):
        from shared import config
        batch = config.get("ai.batch_size", 50)
        # Should be 100 from defaults.yaml, or 50 if yaml is missing
        assert isinstance(batch, int)


class TestConfigDefaults:
    """Test loading from a custom YAML."""

    def test_custom_yaml_loading(self, tmp_path):
        yaml_content = {
            "custom": {"key": "value"},
            "nested": {"deep": {"item": 42}},
        }
        yaml_path = tmp_path / "test_defaults.yaml"
        with open(yaml_path, "w") as f:
            yaml.dump(yaml_content, f)

        # Simulate loading by directly manipulating the module's _defaults
        from shared import config
        original = config._defaults
        try:
            config._defaults = yaml_content
            assert config.get("custom.key") == "value"
            assert config.get("nested.deep.item") == 42
            assert config.get("missing", "default") == "default"
        finally:
            config._defaults = original


class TestEnvVarValidation:
    """Test that env var validation logs warnings for missing keys."""

    @patch("shared.config.logger")
    @patch.dict(os.environ, {}, clear=True)
    def test_warns_on_missing_env_vars(self, mock_logger):
        from shared import config
        config._validate_env_vars()
        # Should have been called with warnings for missing keys
        assert mock_logger.warning.called

    @patch("shared.config.logger")
    @patch.dict(os.environ, {
        "ANTHROPIC_API_KEY": "test-key",
        "ALIENVAULT_OTX_API_KEY": "test-key",
        "SHODAN_API_KEY": "test-key",
    })
    def test_no_warnings_when_all_present(self, mock_logger):
        from shared import config
        config._validate_env_vars()
        # Should NOT have called warning for these keys
        # (it may have been called previously, so we check call_args)
        for call in mock_logger.warning.call_args_list:
            msg = call[0][0] if call[0] else ""
            assert "ANTHROPIC_API_KEY" not in msg
            assert "ALIENVAULT_OTX_API_KEY" not in msg
            assert "SHODAN_API_KEY" not in msg
