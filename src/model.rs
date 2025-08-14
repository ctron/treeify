use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct PaginatedResult<T> {
    pub items: Vec<T>,
    pub total: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct Node {
    pub sbom_id: String,
    pub node_id: String,
    pub purl: Vec<String>,
    pub cpe: Vec<String>,
    pub name: String,
    pub published: String,
    pub document_id: String,
    #[serde(default)]
    pub product_name: Option<String>,
    #[serde(default)]
    pub product_version: Option<String>,
    #[serde(default)]
    pub relationship: Option<String>,
    #[serde(default)]
    pub ancestors: Vec<Node>,
    #[serde(default)]
    pub descendants: Vec<Node>,
}

impl Node {
    pub fn as_key(&self) -> Key {
        Key {
            sbom: self.sbom_id.clone(),
            node: self.node_id.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Key {
    pub sbom: String,
    pub node: String,
}

impl Display for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}--{}", self.sbom, self.node)
    }
}
