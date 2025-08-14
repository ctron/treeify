use super::Graph;
use crate::model::Key;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};

impl Key {
    pub fn encode(&self) -> String {
        format!("{}--{}", encode(&self.sbom), encode(&self.node))
    }
}

#[derive(Debug, Default)]
struct Attributes {
    data: HashMap<String, String>,
    subgraph: bool,
}

impl Attributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn subgraph() -> Self {
        Self {
            subgraph: true,
            ..Default::default()
        }
    }

    pub fn add(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }
}

impl Display for Attributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if !self.subgraph {
            f.write_str("[")?;
        }

        for (k, v) in &self.data {
            write!(f, r#""{}" = "{}" "#, encode(k), encode(v))?;

            if self.subgraph {
                writeln!(f, r#";"#)?;
            }
        }

        if !self.subgraph {
            f.write_str("]")?;
        }

        Ok(())
    }
}

fn encode(s: impl AsRef<str>) -> String {
    s.as_ref()
        .replace('\\', "\\\\")
        .replace('\"', "\\\"")
        .to_string()
}

impl Graph {
    pub fn render_grapviz<W>(self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: std::io::Write,
    {
        writeln!(
            w,
            r#"
digraph {{
  concentrate=true;
  rankdir="LR";
  overlap=false;
  newrank=true;
  compount=true;
  splines=polyline;

"#
        )?;

        for (sbom, nodes) in &self.nodes {
            let sbom_doc = self.sboms.get(sbom).expect("SBOM not found");

            writeln!(
                w,
                r#"
subgraph "{id}" {{
{attrs}
"#,
                id = encode(sbom),
                attrs = Attributes::subgraph().add("cluster", "true").add(
                    "label",
                    format!(
                        "{} / {} / {}",
                        sbom_doc.document_id, sbom_doc.published, sbom
                    )
                ),
            )?;

            for node in nodes.values() {
                writeln!(
                    w,
                    r#"  "{sbom}--{node}" {attrs}"#,
                    sbom = encode(&node.sbom_id),
                    node = encode(&node.node_id),
                    attrs = Attributes::new()
                        .add("label", node.node_id.clone())
                        .add("shape", "box")
                )?;
            }

            writeln!(
                w,
                r#"
}}
"#
            )?;
        }

        for ((from, to), rel) in self.relationships {
            writeln!(
                w,
                r#"  "{left}" -> "{right}" {attrs}"#,
                left = from.encode(),
                right = to.encode(),
                attrs = Attributes::new()
                    .add(
                        "group",
                        format!("{left}-{right}", left = from.sbom, right = to.sbom)
                    )
                    .add("label", rel)
            )?;
        }

        writeln!(
            w,
            r#"
}}
"#
        )?;

        Ok(())
    }
}
