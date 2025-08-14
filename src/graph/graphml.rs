use crate::model::Key;
use io_adapters::WriteExtension;
use isx::IsEmpty;
use serde::Serialize;
use std::fmt::Display;

#[derive(strum::Display)]
enum NodeAttr {
    Name,
    SbomId,
    DocumentId,
    Purl,
    Cpe,
}

#[derive(strum::Display)]
enum EdgeAttr {
    Relationship,
}

#[derive(Serialize, Debug, Clone)]
struct GraphML {
    #[serde(rename = "@xmlns")]
    pub xmlns: String,

    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    #[serde(rename = "key")]
    pub keys: Vec<GraphAttribute>,

    pub graph: Graph,
}

#[derive(Serialize, Debug, Clone)]
struct Graph {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@edgedefault")]
    pub edge_default: String,

    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    #[serde(rename = "node")]
    pub nodes: Vec<Node>,
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    #[serde(rename = "edge")]
    pub edges: Vec<Edge>,
}

#[derive(Serialize, Debug, Clone, Default)]
struct GraphAttribute {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@for")]
    pub r#for: String,
    #[serde(rename = "@attr.name")]
    pub title: String,
    #[serde(rename = "@attr.type")]
    pub r#type: String,
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    pub default: Option<String>,
}

#[derive(Serialize, Debug, Clone, Default, IsEmpty)]
struct Data(pub Vec<Attribute>);

impl Data {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(mut self, key: impl Display, value: impl Display) -> Self {
        self.0.push(Attribute {
            key: key.to_string(),
            value: value.to_string(),
        });
        self
    }

    pub fn extend(
        mut self,
        key: impl Display,
        values: impl IntoIterator<Item = impl Display>,
    ) -> Self {
        let key = key.to_string();
        self.0.extend(values.into_iter().map(|value| Attribute {
            key: key.clone(),
            value: value.to_string(),
        }));
        self
    }

    pub fn into_vec(self) -> Vec<Attribute> {
        self.0
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct Attribute {
    #[serde(rename = "@key")]
    pub key: String,
    #[serde(rename = "$text")]
    pub value: String,
}

#[derive(Serialize, Debug, Clone)]
struct Node {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    pub graph: Option<Graph>,
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    #[serde(rename = "data")]
    pub data: Vec<Attribute>,
}

#[derive(Serialize, Debug, Clone)]
struct Edge {
    #[serde(rename = "@id")]
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    pub id: Option<String>,
    #[serde(rename = "@source")]
    pub source: String,
    #[serde(rename = "@target")]
    pub target: String,
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    #[serde(rename = "data")]
    pub data: Vec<Attribute>,
}

impl super::Graph {
    pub fn render_graphml<W>(self, w: &mut W) -> Result<(), anyhow::Error>
    where
        W: std::io::Write,
    {
        let mut nodes = vec![];
        let mut edges = vec![];

        for (sbom, sbom_nodes) in self.nodes {
            let sbom_doc = self.sboms.get(&sbom).expect("sbom doc not found");

            let mut children = vec![];
            for node in sbom_nodes.values() {
                let key = Key {
                    sbom: sbom.clone(),
                    node: node.node_id.clone(),
                };
                children.push(Node {
                    id: key.to_string(),
                    graph: Default::default(),
                    data: Data::new()
                        .add(NodeAttr::Name, node.name.clone())
                        .add(NodeAttr::SbomId, sbom.clone())
                        .add(NodeAttr::DocumentId, node.document_id.clone())
                        .extend(NodeAttr::Cpe, &node.cpe)
                        .extend(NodeAttr::Purl, &node.purl)
                        .into_vec(),
                })
            }

            nodes.push(Node {
                id: sbom.clone(),
                data: Data::new()
                    .add(NodeAttr::DocumentId, sbom_doc.document_id.clone())
                    .into_vec(),
                graph: Some(Graph {
                    id: sbom.clone(),
                    edge_default: "directed".to_string(),
                    nodes: children,
                    edges: vec![],
                }),
            });
        }

        for ((from, to), rel) in self.relationships {
            edges.push(Edge {
                id: None,
                source: from.to_string(),
                target: to.to_string(),
                data: Data::new().add(EdgeAttr::Relationship, rel).into_vec(),
            })
        }

        let gml = GraphML {
            xmlns: "http://graphml.graphdrawing.org/xmlns".into(),
            keys: vec![
                GraphAttribute {
                    id: NodeAttr::Name.to_string(),
                    r#for: "node".to_string(),
                    title: "Name".to_string(),
                    r#type: "string".to_string(),
                    default: None,
                },
                GraphAttribute {
                    id: NodeAttr::SbomId.to_string(),
                    r#for: "node".to_string(),
                    title: "SBOM ID".to_string(),
                    r#type: "string".to_string(),
                    default: None,
                },
                GraphAttribute {
                    id: NodeAttr::DocumentId.to_string(),
                    r#for: "node".to_string(),
                    title: "Document ID".to_string(),
                    r#type: "string".to_string(),
                    default: None,
                },
                GraphAttribute {
                    id: NodeAttr::Cpe.to_string(),
                    r#for: "node".to_string(),
                    title: "CPE".to_string(),
                    r#type: "string".to_string(),
                    default: None,
                },
                GraphAttribute {
                    id: NodeAttr::Purl.to_string(),
                    r#for: "node".to_string(),
                    title: "PURL".to_string(),
                    r#type: "string".to_string(),
                    default: None,
                },
                GraphAttribute {
                    id: EdgeAttr::Relationship.to_string(),
                    r#for: "edge".to_string(),
                    title: "Relationship".to_string(),
                    r#type: "string".to_string(),
                    default: None,
                },
            ],
            graph: Graph {
                id: "ID".into(),
                edge_default: "directed".to_string(),
                nodes,
                edges,
            },
        };

        quick_xml::se::to_writer_with_root(w.write_adapter(), "graphml", &gml)?;

        Ok(())
    }
}
