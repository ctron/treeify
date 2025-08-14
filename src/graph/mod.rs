mod gexf;
mod graphml;
mod graphviz;

use crate::model::{Key, Node};
use std::collections::HashMap;

struct Sbom {
    document_id: String,
    published: String,
}

pub struct Graph {
    sboms: HashMap<String, Sbom>,
    nodes: HashMap<String, HashMap<String, Node>>,
    relationships: HashMap<(Key, Key), String>,
}

impl Graph {
    pub fn new(input: &[Node]) -> Self {
        let mut sboms = HashMap::new();
        let mut nodes = HashMap::new();
        let mut relationships = HashMap::new();

        fn scan(
            sboms: &mut HashMap<String, Sbom>,
            nodes: &mut HashMap<String, HashMap<String, Node>>,
            relationships: &mut HashMap<(Key, Key), String>,
            input: &[Node],
            parent: Option<&Node>,
            reverse: bool,
        ) {
            for node in input {
                sboms.entry(node.sbom_id.clone()).or_insert_with(|| Sbom {
                    document_id: node.document_id.clone(),
                    published: node.published.clone(),
                });

                if let (Some(parent), Some(rel)) = (parent, &node.relationship) {
                    if reverse {
                        relationships.insert((node.as_key(), parent.as_key()), rel.clone());
                    } else {
                        relationships.insert((parent.as_key(), node.as_key()), rel.clone());
                    }
                }

                nodes
                    .entry(node.sbom_id.clone())
                    .or_default()
                    .insert(node.node_id.clone(), node.clone());

                scan(
                    sboms,
                    nodes,
                    relationships,
                    &node.ancestors,
                    Some(node),
                    true,
                );
                scan(
                    sboms,
                    nodes,
                    relationships,
                    &node.descendants,
                    Some(node),
                    false,
                );
            }
        }

        scan(
            &mut sboms,
            &mut nodes,
            &mut relationships,
            input,
            None,
            false,
        );

        Self {
            sboms,
            nodes,
            relationships,
        }
    }
}
