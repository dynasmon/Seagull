import type { TopologyEdge, TopologyGraph, TopologyGroup, TopologyNode } from "../../types";

function text(value: unknown): string {
  return String(value ?? "").toLowerCase();
}

function nodeMatchesQuery(node: TopologyNode, query: string): boolean {
  return (
    text(node.label).includes(query) ||
    text(node.ip).includes(query) ||
    text(node.cidr).includes(query) ||
    text(node.protocol).includes(query) ||
    text(node.port).includes(query) ||
    text(node.agent_id).includes(query) ||
    text(node.metadata?.hostname).includes(query) ||
    text(node.metadata?.service_name).includes(query)
  );
}

function groupMatchesQuery(group: TopologyGroup, query: string): boolean {
  return (
    text(group.label).includes(query) ||
    text(group.agent_id).includes(query) ||
    text(group.cidr).includes(query)
  );
}

function edgeMatchesQuery(
  edge: TopologyEdge,
  nodeByKey: Map<string, TopologyNode>,
  query: string,
): boolean {
  const src = nodeByKey.get(edge.source_node_key);
  const tgt = nodeByKey.get(edge.target_node_key);
  return (
    text(edge.edge_type).includes(query) ||
    text(edge.protocol).includes(query) ||
    text(edge.port).includes(query) ||
    (src ? nodeMatchesQuery(src, query) : false) ||
    (tgt ? nodeMatchesQuery(tgt, query) : false)
  );
}

export type TopologySearchResult = {
  matchedNodeKeys: Set<string>;
  matchedEdgeKeys: Set<string>;
  matchedGroupKeys: Set<string>;
  orderedNodeKeys: string[];
  orderedGroupKeys: string[];
};

const EMPTY_RESULT: TopologySearchResult = {
  matchedNodeKeys: new Set(),
  matchedEdgeKeys: new Set(),
  matchedGroupKeys: new Set(),
  orderedNodeKeys: [],
  orderedGroupKeys: [],
};

export function searchTopologyGraph(
  graph: TopologyGraph | null,
  groups: TopologyGroup[],
  query: string,
): TopologySearchResult {
  const q = query.trim().toLowerCase();
  if (!q || !graph) return EMPTY_RESULT;

  const nodeByKey = new Map(graph.nodes.map((n) => [n.node_key, n]));

  const matchedNodeKeys = new Set<string>();
  const orderedNodeKeys: string[] = [];
  for (const node of graph.nodes) {
    if (nodeMatchesQuery(node, q)) {
      matchedNodeKeys.add(node.node_key);
      orderedNodeKeys.push(node.node_key);
    }
  }

  const matchedEdgeKeys = new Set<string>();
  for (const edge of graph.edges) {
    if (edgeMatchesQuery(edge, nodeByKey, q)) {
      matchedEdgeKeys.add(edge.edge_key);
    }
  }

  const matchedGroupKeys = new Set<string>();
  const orderedGroupKeys: string[] = [];
  for (const group of groups) {
    if (groupMatchesQuery(group, q)) {
      matchedGroupKeys.add(group.group_key);
      orderedGroupKeys.push(group.group_key);
    }
  }

  return { matchedNodeKeys, matchedEdgeKeys, matchedGroupKeys, orderedNodeKeys, orderedGroupKeys };
}
