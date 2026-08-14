# ============================================================
#  Tests — Module B (GNN + MITRE + Defense Engine)
# ============================================================

import pytest
import torch
from src.module_b.gnn_model import ThreatGNN, build_node_features, graph_snapshot_to_pyg, NUM_NODE_FEATURES
from src.module_b.mitre_mapper import MitreMapper
from src.module_b.defense_engine import DefenseEngine, ActionSeverity, ActionStatus


# ── GNN Model Tests ───────────────────────────────────────────

class TestThreatGNN:

    def test_model_instantiation(self):
        model = ThreatGNN(in_channels=NUM_NODE_FEATURES, hidden_channels=32, num_layers=2)
        assert model is not None

    def test_forward_pass(self):
        model = ThreatGNN(in_channels=NUM_NODE_FEATURES, hidden_channels=32, num_layers=2)
        model.eval()

        # 5 nodes, edges: 0→1, 1→2, 2→3, 3→4
        x = torch.randn(5, NUM_NODE_FEATURES)
        edge_index = torch.tensor([[0, 1, 2, 3], [1, 2, 3, 4]], dtype=torch.long)

        with torch.no_grad():
            out = model(x, edge_index)

        assert out.shape == (5, 1)
        assert (out >= 0).all() and (out <= 1).all()

    def test_output_is_probability(self):
        model = ThreatGNN()
        model.eval()
        x = torch.rand(3, NUM_NODE_FEATURES)
        ei = torch.tensor([[0, 1], [1, 2]], dtype=torch.long)
        with torch.no_grad():
            out = model(x, ei)
        assert ((out >= 0.0) & (out <= 1.0)).all()

    def test_node_features_shape(self):
        nodes = [
            {"label": "User",    "risk_score": 0.8, "connection_count": 5},
            {"label": "Machine", "risk_score": 0.3, "connection_count": 12},
            {"label": "Process", "risk_score": 0.9, "connection_count": 2},
        ]
        feats = build_node_features(nodes)
        assert feats.shape == (3, NUM_NODE_FEATURES)

    def test_graph_snapshot_conversion(self):
        snapshot = {
            "nodes": [
                {"id": 1, "label": "User",    "name": "alice",  "risk_score": 0.7},
                {"id": 2, "label": "Machine", "name": "WS-001", "risk_score": 0.5},
            ],
            "edges": [
                {"source": 1, "target": 2, "rel_type": "LOGGED_IN", "weight": 0.7}
            ],
        }
        data, id_map, nodes = graph_snapshot_to_pyg(snapshot)
        assert data.num_nodes == 2
        assert data.edge_index.shape[1] == 1
        assert 1 in id_map and 2 in id_map


# ── MITRE Mapper Tests ────────────────────────────────────────

class TestMitreMapper:

    def setup_method(self):
        self.mapper = MitreMapper()

    def test_map_user_node(self):
        node = {"node_label": "User", "node_name": "alice", "threat_score": 0.85}
        result = self.mapper.map_node_to_attack(node)
        assert "technique_id" in result
        assert "tactic" in result
        assert "mitigations" in result
        assert isinstance(result["mitigations"], list)

    def test_map_machine_node(self):
        node = {"node_label": "Machine", "node_name": "WS-001", "threat_score": 0.78}
        result = self.mapper.map_node_to_attack(node)
        assert result["technique_id"].startswith("T")

    def test_kill_chain_position_is_int(self):
        node = {"node_label": "Process", "node_name": "mimikatz.exe", "threat_score": 0.99}
        result = self.mapper.map_node_to_attack(node)
        assert isinstance(result["kill_chain_position"], int)

    def test_unknown_technique_fallback(self):
        result = MitreMapper._unknown_technique()
        assert result["technique_id"] == "T0000"


# ── Defense Engine Tests ──────────────────────────────────────

class TestDefenseEngine:

    def setup_method(self):
        self.engine = DefenseEngine()

    def test_low_score_alert_only(self):
        node = {"node_label": "User", "node_name": "alice", "threat_score": 0.30}
        mitre = {"technique_id": "T1078", "severity": "low"}
        recs = self.engine.generate_recommendations(node, mitre)
        # Should only produce alert action
        types = [r["action_type"] for r in recs]
        assert "alert" in types
        assert "network_quarantine" not in types

    def test_high_score_produces_quarantine(self):
        node = {"node_label": "Machine", "node_name": "SRV-DC1", "threat_score": 0.90}
        mitre = {"technique_id": "T1021", "severity": "critical"}
        recs = self.engine.generate_recommendations(node, mitre)
        types = [r["action_type"] for r in recs]
        assert "network_quarantine" in types

    def test_critical_user_gets_account_disable(self):
        node = {"node_label": "User", "node_name": "alice", "threat_score": 0.92}
        mitre = {"technique_id": "T1548", "severity": "critical"}
        recs = self.engine.generate_recommendations(node, mitre)
        types = [r["action_type"] for r in recs]
        assert "disable_account" in types

    def test_high_action_is_pending(self):
        node = {"node_label": "Machine", "node_name": "SRV-DB", "threat_score": 0.88}
        mitre = {"technique_id": "T1021", "severity": "high"}
        recs = self.engine.generate_recommendations(node, mitre)
        high_recs = [r for r in recs if r["severity"] in ("high", "critical")]
        for r in high_recs:
            # If Redis is not connected, status may be AUTO but logged
            assert r["status"] in ("pending", "auto")
