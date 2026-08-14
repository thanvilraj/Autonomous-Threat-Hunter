# ============================================================
#  Module B — Graph Neural Network Model (PyTorch Geometric)
#
#  Architecture: GraphSAGE (3 layers) + MLP head
#  Task: Node-level threat score prediction
#  Input:  Network graph from Neo4j (nodes + edges)
#  Output: Per-node threat probability [0.0 – 1.0]
#
#  Note: Uses PyG native ops — torch-scatter/torch-sparse
#  are NOT required (Python 3.14 + torch 2.13+ compatible).
# ============================================================

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch import Tensor
from torch_geometric.nn import SAGEConv
from torch_geometric.nn.norm import BatchNorm
from torch_geometric.data import Data
from loguru import logger

from src.config.settings import get_settings


# ── Node Feature Encoding ─────────────────────────────────────

NODE_TYPE_MAP = {
    "User":      0,
    "Machine":   1,
    "Process":   2,
    "File":      3,
    "IPAddress": 4,
    "Unknown":   5,
}

NUM_NODE_TYPES    = len(NODE_TYPE_MAP)
NUM_NODE_FEATURES = NUM_NODE_TYPES + 2   # one-hot type + risk_score + connection_count


def build_node_features(nodes: list[dict]) -> Tensor:
    """
    Convert Neo4j node dicts → float tensor of shape [N, NUM_NODE_FEATURES].

    Features per node:
      [0:6]  — one-hot encoded node type
      [6]    — normalised risk_score (0.0–1.0)
      [7]    — placeholder for connection_count (to be enriched later)
    """
    features = []
    for node in nodes:
        label = node.get("label", "Unknown")
        type_idx = NODE_TYPE_MAP.get(label, NODE_TYPE_MAP["Unknown"])
        one_hot = [0.0] * NUM_NODE_TYPES
        one_hot[type_idx] = 1.0

        risk = float(node.get("risk_score") or 0.0)
        conn = float(node.get("connection_count") or 0.0) / 100.0   # normalise

        features.append(one_hot + [risk, conn])

    return torch.tensor(features, dtype=torch.float)


def build_edge_index(edges: list[dict], node_id_map: dict[int, int]) -> Tensor:
    """Convert edge list to COO format edge_index tensor [2, E]."""
    src_list, dst_list = [], []
    for edge in edges:
        src_neo4j = edge.get("source")
        dst_neo4j = edge.get("target")
        if src_neo4j in node_id_map and dst_neo4j in node_id_map:
            src_list.append(node_id_map[src_neo4j])
            dst_list.append(node_id_map[dst_neo4j])

    if not src_list:
        return torch.zeros((2, 0), dtype=torch.long)

    return torch.tensor([src_list, dst_list], dtype=torch.long)


def graph_snapshot_to_pyg(snapshot: dict) -> tuple[Data, dict, list]:
    """
    Convert a Neo4j graph snapshot dict into a PyTorch Geometric Data object.

    Returns:
        data:        PyG Data object
        node_id_map: mapping neo4j_id → pyg_idx
        nodes:       original node list (for label lookup)
    """
    nodes = snapshot.get("nodes", [])
    edges = snapshot.get("edges", [])

    # Build Neo4j ID → sequential PyG index map
    node_id_map = {node["id"]: idx for idx, node in enumerate(nodes)}

    x          = build_node_features(nodes)
    edge_index = build_edge_index(edges, node_id_map)

    data = Data(x=x, edge_index=edge_index)
    data.num_nodes = len(nodes)

    return data, node_id_map, nodes


# ── GraphSAGE + Attention Model ───────────────────────────────

class ThreatGNN(nn.Module):
    """
    Graph Neural Network for per-node threat prediction.

    Architecture:
      - 3× GraphSAGE layers (native PyTorch ops, no torch-scatter needed)
      - BatchNorm + ReLU + Dropout between layers
      - Final MLP head → sigmoid → threat probability

    Input:  node features [N, NUM_NODE_FEATURES]
    Output: threat scores [N, 1] — values in (0, 1)
    """

    def __init__(
        self,
        in_channels:     int   = NUM_NODE_FEATURES,
        hidden_channels: int   = 64,
        num_layers:      int   = 3,
        dropout:         float = 0.3,
    ):
        super().__init__()
        self.dropout = dropout

        # GraphSAGE layers
        self.convs = nn.ModuleList()
        self.bns   = nn.ModuleList()

        self.convs.append(SAGEConv(in_channels, hidden_channels))
        self.bns.append(BatchNorm(hidden_channels))

        for _ in range(num_layers - 2):
            self.convs.append(SAGEConv(hidden_channels, hidden_channels))
            self.bns.append(BatchNorm(hidden_channels))

        self.convs.append(SAGEConv(hidden_channels, hidden_channels // 2))
        self.bns.append(BatchNorm(hidden_channels // 2))

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_channels // 2, 32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: Tensor, edge_index: Tensor) -> Tensor:
        for conv, bn in zip(self.convs, self.bns):
            x = conv(x, edge_index)
            x = bn(x)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)

        return self.classifier(x)  # [N, 1]


# ── Model Manager ────────────────────────────────────────────

class GNNModelManager:
    """Manages loading, saving, and inference of the ThreatGNN model."""

    MODEL_PATH = "data/models/threat_gnn.pt"

    def __init__(self):
        self.settings = get_settings()
        self.device   = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model    = ThreatGNN(
            hidden_channels=self.settings.gnn_hidden_channels,
            num_layers=self.settings.gnn_num_layers,
        ).to(self.device)
        logger.info(f"🧠 ThreatGNN initialized on {self.device}")

    def load_weights(self) -> bool:
        """Load pre-trained weights if they exist."""
        import os
        if os.path.exists(self.MODEL_PATH):
            self.model.load_state_dict(
                torch.load(self.MODEL_PATH, map_location=self.device)
            )
            self.model.eval()
            logger.success(f"✅ Model weights loaded from {self.MODEL_PATH}")
            return True
        logger.warning("⚠️  No saved model weights found — using random init")
        return False

    def save_weights(self) -> None:
        import os
        os.makedirs(os.path.dirname(self.MODEL_PATH), exist_ok=True)
        torch.save(self.model.state_dict(), self.MODEL_PATH)
        logger.info(f"💾 Model weights saved to {self.MODEL_PATH}")

    @torch.no_grad()
    def predict(self, snapshot: dict) -> list[dict]:
        """
        Run inference on a graph snapshot.

        Returns list of dicts:
          { node_name, node_label, threat_score, is_threat }
        """
        if not snapshot.get("nodes"):
            logger.warning("Empty graph snapshot — skipping prediction")
            return []

        data, node_id_map, nodes = graph_snapshot_to_pyg(snapshot)
        data = data.to(self.device)

        self.model.eval()
        scores: Tensor = self.model(data.x, data.edge_index)   # [N, 1]
        scores_np = scores.cpu().numpy().flatten()

        threshold = self.settings.threat_score_threshold
        results = []
        for idx, node in enumerate(nodes):
            score = float(scores_np[idx])
            results.append({
                "node_id":     node.get("id"),
                "node_name":   node.get("name", "unknown"),
                "node_label":  node.get("label", "Unknown"),
                "threat_score": round(score, 4),
                "is_threat":   score >= threshold,
            })

        results.sort(key=lambda x: x["threat_score"], reverse=True)
        threats = [r for r in results if r["is_threat"]]
        logger.info(f"🔍 Prediction complete: {len(threats)} threat nodes detected out of {len(nodes)}")
        return results

    def train_on_snapshot(self, snapshot: dict, labels: list[float], epochs: int = 50):
        """
        Mini supervised training step.

        labels: list of ground-truth threat scores per node [0.0 or 1.0]
        In production: use historical incident data to build this.
        """
        data, _, _ = graph_snapshot_to_pyg(snapshot)
        data = data.to(self.device)
        y = torch.tensor(labels, dtype=torch.float).unsqueeze(1).to(self.device)

        self.model.train()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.005, weight_decay=5e-4)
        criterion = nn.BCELoss()

        for epoch in range(epochs):
            optimizer.zero_grad()
            out  = self.model(data.x, data.edge_index)
            loss = criterion(out, y)
            loss.backward()
            optimizer.step()

            if epoch % 10 == 0:
                logger.debug(f"  Epoch {epoch:03d} | Loss: {loss.item():.4f}")

        logger.success(f"✅ Training complete over {epochs} epochs")
        self.save_weights()
