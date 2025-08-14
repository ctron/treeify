use crate::model::Key;
use io_adapters::WriteExtension;
use isx::IsEmpty;
use serde::Serialize;
use std::borrow::Cow;
use std::fmt::Display;
use time::OffsetDateTime;

#[derive(strum::Display)]
enum Attr {
    SbomId,
    DocumentId,
    Purl,
    Cpe,
}

#[derive(Serialize, Debug, Clone)]
struct Gexf {
    #[serde(rename = "@version")]
    pub version: String,
    #[serde(rename = "@xmlns")]
    pub xmlns: String,

    pub meta: Meta,
    pub graph: Graph,
}

#[derive(Serialize, Debug, Clone)]
struct Meta {
    #[serde(with = "time::serde::rfc3339")]
    #[serde(rename = "@lastmodifieddate")]
    pub last_modified_date: OffsetDateTime,

    pub creator: Cow<'static, str>,

    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    pub description: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
struct Graph {
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    #[serde(rename = "@mode")]
    pub mode: Option<String>,
    #[serde(rename = "@defaultedgetype")]
    pub default_edge_type: String,

    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    pub attributes: GraphAttributes,

    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    pub nodes: Nodes,
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    pub edges: Edges,
}

#[derive(Serialize, Debug, Clone, Default, IsEmpty)]
struct GraphAttributes {
    #[serde(rename = "@class")]
    pub class: String,
    #[serde(rename = "@mode")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    #[serde(rename = "attribute")]
    pub attributes: Vec<GraphAttribute>,
}

#[derive(Serialize, Debug, Clone, Default)]
struct GraphAttribute {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@title")]
    pub title: String,
    #[serde(rename = "@type")]
    pub r#type: String,
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    pub default: Option<String>,
}

#[derive(Serialize, Debug, Clone, Default, IsEmpty)]
struct Nodes {
    pub node: Vec<Node>,
}

#[derive(Serialize, Debug, Clone, Default, IsEmpty)]
struct Edges {
    pub edge: Vec<Edge>,
}

#[derive(Serialize, Debug, Clone, Default, IsEmpty)]
struct Attributes {
    #[serde(rename = "attvalue")]
    pub attribute: Vec<Attribute>,
}

impl Attributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(mut self, r#for: impl Display, value: impl Display) -> Self {
        self.attribute.push(Attribute {
            r#for: r#for.to_string(),
            value: value.to_string(),
        });
        self
    }

    pub fn extend(
        mut self,
        r#for: impl Display,
        values: impl IntoIterator<Item = impl Display>,
    ) -> Self {
        let r#for = r#for.to_string();
        self.attribute
            .extend(values.into_iter().map(|value| Attribute {
                r#for: r#for.clone(),
                value: value.to_string(),
            }));
        self
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct Attribute {
    #[serde(rename = "@for")]
    pub r#for: String,
    #[serde(rename = "@value")]
    pub value: String,
}

#[derive(Serialize, Debug, Clone)]
struct Node {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@pid")]
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    pub pid: Option<String>,
    #[serde(rename = "@label")]
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    pub nodes: Nodes,
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    #[serde(rename = "attvalues")]
    pub attributes: Attributes,
}

#[derive(Serialize, Debug, Clone)]
struct Edge {
    #[serde(rename = "@source")]
    pub source: String,
    #[serde(rename = "@target")]
    pub target: String,
    #[serde(rename = "@label")]
    #[serde(skip_serializing_if = "IsEmpty::is_empty")]
    pub label: Option<String>,
}

impl super::Graph {
    pub fn render_gexf<W>(self, w: &mut W) -> Result<(), anyhow::Error>
    where
        W: std::io::Write,
    {
        let mut nodes = vec![];
        let mut edges = vec![];

        for (sbom, sbom_nodes) in self.nodes {
            for node in sbom_nodes.values() {
                let key = Key {
                    sbom: sbom.clone(),
                    node: node.node_id.clone(),
                };
                nodes.push(Node {
                    id: key.to_string(),
                    pid: None,
                    label: Some(node.name.clone()),
                    nodes: Default::default(),
                    attributes: Attributes::new()
                        .add(Attr::SbomId, sbom.clone())
                        .add(Attr::DocumentId, node.document_id.clone())
                        .extend(Attr::Cpe, &node.cpe)
                        .extend(Attr::Purl, &node.purl),
                })
            }
        }

        for ((from, to), rel) in self.relationships {
            edges.push(Edge {
                source: from.to_string(),
                target: to.to_string(),
                label: Some(rel),
            })
        }

        let gexf = Gexf {
            version: "1.3".into(),
            xmlns: "http://gexf.net/1.3".into(),
            meta: Meta {
                creator: "treeify".into(),
                description: None,
                last_modified_date: OffsetDateTime::now_utc(),
            },
            graph: Graph {
                mode: Some("static".into()),
                default_edge_type: "directed".to_string(),
                attributes: GraphAttributes {
                    class: "node".into(),
                    mode: None,
                    attributes: vec![
                        GraphAttribute {
                            id: Attr::SbomId.to_string(),
                            title: "SBOM ID".to_string(),
                            r#type: "string".to_string(),
                            default: None,
                        },
                        GraphAttribute {
                            id: Attr::DocumentId.to_string(),
                            title: "Document ID".to_string(),
                            r#type: "string".to_string(),
                            default: None,
                        },
                        GraphAttribute {
                            id: Attr::Cpe.to_string(),
                            title: "CPE".to_string(),
                            r#type: "liststring".to_string(),
                            default: None,
                        },
                        GraphAttribute {
                            id: Attr::Purl.to_string(),
                            title: "PURL".to_string(),
                            r#type: "liststring".to_string(),
                            default: None,
                        },
                    ],
                },
                nodes: Nodes { node: nodes },
                edges: Edges { edge: edges },
            },
        };

        quick_xml::se::to_writer_with_root(w.write_adapter(), "gexf", &gexf)?;

        Ok(())
    }
}
