"""Tests für evaluation/config.py — EvaluationConfig, RiskWeights, YAML-Merge."""
import pytest
import yaml
from pathlib import Path
from shodan_report.evaluation.config import EvaluationConfig, RiskWeights


# ── RiskWeights Defaults ──────────────────────────────────────────────────────

class TestRiskWeightsDefaults:
    def test_open_ports_defaults_exist(self):
        w = RiskWeights()
        assert "thresholds" in w.open_ports
        assert "scores" in w.open_ports

    def test_high_risk_services_defaults_exist(self):
        w = RiskWeights()
        assert "rdp_unencrypted" in w.high_risk_services
        assert "telnet" in w.high_risk_services

    def test_secure_indicators_defaults(self):
        w = RiskWeights()
        assert "tls" in w.secure_indicators
        assert "ssl" in w.secure_indicators

    def test_defaults_are_independent_instances(self):
        """Zwei RiskWeights-Instanzen teilen keinen Zustand."""
        a = RiskWeights()
        b = RiskWeights()
        a.high_risk_services["new_key"] = 99
        assert "new_key" not in b.high_risk_services


# ── EvaluationConfig ohne Config-Datei ───────────────────────────────────────

class TestEvaluationConfigNoFile:
    def test_default_construction_succeeds(self, tmp_path, monkeypatch):
        """Ohne config/evaluation.yaml → läuft mit Defaults durch."""
        monkeypatch.chdir(tmp_path)
        cfg = EvaluationConfig()
        assert isinstance(cfg.weights, RiskWeights)

    def test_nonexistent_explicit_path_uses_defaults(self, tmp_path):
        cfg = EvaluationConfig(config_path=str(tmp_path / "nonexistent.yaml"))
        assert cfg.weights.high_risk_services["telnet"] == 4

    def test_to_dict_returns_expected_keys(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = EvaluationConfig()
        d = cfg.to_dict()
        assert "risk_weights" in d
        assert "open_ports" in d["risk_weights"]
        assert "high_risk_services" in d["risk_weights"]


# ── EvaluationConfig mit gültigem YAML ───────────────────────────────────────

class TestEvaluationConfigValidYaml:
    def _write_yaml(self, path: Path, data: dict):
        path.write_text(yaml.dump(data), encoding="utf-8")
        return str(path)

    def test_load_overrides_open_ports_thresholds(self, tmp_path):
        p = self._write_yaml(tmp_path / "cfg.yaml", {
            "risk_weights": {"open_ports": {"thresholds": [5, 10, 20]}}
        })
        cfg = EvaluationConfig(config_path=p)
        assert cfg.weights.open_ports["thresholds"] == [5, 10, 20]

    def test_load_overrides_high_risk_service_score(self, tmp_path):
        p = self._write_yaml(tmp_path / "cfg.yaml", {
            "risk_weights": {"high_risk_services": {"telnet": 99}}
        })
        cfg = EvaluationConfig(config_path=p)
        assert cfg.weights.high_risk_services["telnet"] == 99

    def test_load_preserves_unset_defaults(self, tmp_path):
        """Nur geänderte Felder werden überschrieben — andere bleiben."""
        p = self._write_yaml(tmp_path / "cfg.yaml", {
            "risk_weights": {"high_risk_services": {"telnet": 1}}
        })
        cfg = EvaluationConfig(config_path=p)
        assert "rdp_unencrypted" in cfg.weights.high_risk_services

    def test_load_adds_new_service_key(self, tmp_path):
        p = self._write_yaml(tmp_path / "cfg.yaml", {
            "risk_weights": {"high_risk_services": {"my_custom_service": 7}}
        })
        cfg = EvaluationConfig(config_path=p)
        assert cfg.weights.high_risk_services["my_custom_service"] == 7

    def test_config_without_risk_weights_key(self, tmp_path):
        """YAML ohne 'risk_weights'-Key → kein Fehler, Defaults bleiben."""
        p = self._write_yaml(tmp_path / "cfg.yaml", {"other_key": "irrelevant"})
        cfg = EvaluationConfig(config_path=p)
        assert cfg.weights.high_risk_services["telnet"] == 4

    def test_default_path_loaded_when_exists(self, tmp_path, monkeypatch):
        """config/evaluation.yaml im cwd wird automatisch geladen."""
        monkeypatch.chdir(tmp_path)
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        self._write_yaml(config_dir / "evaluation.yaml", {
            "risk_weights": {"high_risk_services": {"telnet": 77}}
        })
        cfg = EvaluationConfig()
        assert cfg.weights.high_risk_services["telnet"] == 77


# ── EvaluationConfig mit ungültigem YAML ─────────────────────────────────────

class TestEvaluationConfigBadYaml:
    def test_bad_yaml_on_explicit_path_raises(self, tmp_path):
        """Ungültiges YAML bei explizitem Pfad → Exception (kein silent fail)."""
        p = tmp_path / "bad.yaml"
        p.write_text(": invalid: yaml: [unclosed", encoding="utf-8")
        with pytest.raises(Exception):
            EvaluationConfig(config_path=str(p))

    def test_bad_yaml_on_default_path_silently_ignored(self, tmp_path, monkeypatch):
        """Ungültiges YAML am Default-Pfad → EvaluationConfig trotzdem lauffähig."""
        monkeypatch.chdir(tmp_path)
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "evaluation.yaml").write_text(": invalid: yaml: [unclosed", encoding="utf-8")
        cfg = EvaluationConfig()
        assert isinstance(cfg.weights, RiskWeights)
