mod graph;
mod model;

use crate::graph::Graph;
use crate::model::{Node, PaginatedResult};
use anyhow::anyhow;
use clap::Parser;
use futures_util::{StreamExt, stream};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use reqwest::Url;
use std::collections::BTreeSet;
use std::io::stdout;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use urlencoding::encode;

#[derive(Debug, clap::Parser)]
#[command(version, about)]
struct Options {
    #[arg()]
    input: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    Graphml,
    Gexf,
    Graphviz,
    Fetch {
        #[arg(short, long)]
        url: Url,
        #[arg(short, long)]
        bearer: Option<String>,
        #[arg(short = 'O', long)]
        output: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let options = Options::parse();

    let items: PaginatedResult<Node> =
        serde_json::from_reader(std::fs::File::open(options.input)?)?;

    match options.command {
        Command::Graphviz => {
            let graph = Graph::new(&items.items);
            graph.render_grapviz(&mut stdout().lock())?;
        }
        Command::Graphml => {
            let graph = Graph::new(&items.items);
            graph.render_graphml(&mut stdout().lock())?
        }
        Command::Gexf => {
            let graph = Graph::new(&items.items);
            graph.render_gexf(&mut stdout().lock())?
        }
        Command::Fetch {
            url,
            bearer,
            output,
        } => {
            let mut sboms = BTreeSet::new();

            fn scan(input: &[Node], sboms: &mut BTreeSet<String>) {
                for node in input {
                    sboms.insert(node.sbom_id.clone());
                    scan(&node.ancestors, sboms);
                    scan(&node.descendants, sboms);
                }
            }

            scan(&items.items, &mut sboms);

            fetch(&url, output, bearer, sboms)?;
        }
    }

    Ok(())
}

fn fetch(
    url: &Url,
    output: Option<PathBuf>,
    bearer: Option<String>,
    sboms: BTreeSet<String>,
) -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;

    let client = reqwest::Client::new();
    let m = MultiProgress::new();

    let result = rt.block_on(async {
        stream::iter(sboms)
            .map(|id| {
                let url = url.join(&format!(
                    "/api/v2/sbom/{key}/download",
                    key = encode(&format!("urn:uuid:{id}"))
                ));

                let pb = m.add(ProgressBar::new(0));

                let client = client.clone();
                let bearer = bearer.clone();
                let output = output.clone();

                rt.spawn(async move {
                    let name = format!("{id}.json");
                    let name: PathBuf = match output {
                        Some(path) =>
                            path.join(name),
                        None => { name.into() }
                    };

                    let url = url?;

                    pb.set_style(
                        ProgressStyle::with_template(
                            "{spinner:.green} [{elapsed_precise}] {wide_bar:.cyan/blue} {bytes}/{total_bytes} (({bytes_per_sec}, {eta}) {msg}",
                        )
                            ?
                            .progress_chars("#>-"),
                    );

                    let mut req = client.get(url.clone());

                    if let Some(bearer) = bearer {
                        req = req.bearer_auth(bearer);
                    }

                    match req.send().await.and_then(|resp| resp.error_for_status()) {
                        Ok(resp) => {
                            let total_size = resp.content_length().unwrap_or(0);
                            pb.set_length(total_size);

                            let mut file = File::create(&name).await?;
                            let mut stream = resp.bytes_stream();

                            while let Some(chunk) = stream.next().await {
                                let chunk = chunk?;
                                file.write_all(&chunk).await?;
                                pb.inc(chunk.len() as u64);
                            }

                            file.flush().await?;

                            pb.finish_and_clear();
                            println!("[{url}] Done");
                            Ok::<_, anyhow::Error>(())
                        }
                        Err(e) => {
                            pb.finish_and_clear();
                            eprintln!("[{name}] ERROR: {e}", name = name.display());
                            Err(anyhow!("download failed for: {url}"))
                        }
                    }
                })
            })
            .buffer_unordered(5)
            .collect::<Vec<_>>()
            .await
    });

    let _x = result
        .into_iter()
        .map(|outer| outer.map_err(anyhow::Error::from)?)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(())
}
