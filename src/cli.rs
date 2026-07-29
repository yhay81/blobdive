use std::{
    collections::BTreeMap,
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use schemars::schema_for;
use serde::Serialize;
use serde_json::Value;

use crate::{
    engine::{
        adapters, detect_source, inspect_source, list_reference, read_reference, InspectOptions,
        ReadOptions,
    },
    error::BlobError,
    model::{
        AdaptersResult, ArtifactNode, BriefContract, BudgetLimits, DetectResult, ErrorEnvelope,
        InspectResult, ListResult, ReadResult, VERSION,
    },
};

#[derive(Debug, Parser)]
#[command(
    name = "blobdive",
    version,
    about = "Bounded, read-only inspection of nested software artifacts",
    long_about = None
)]
struct Cli {
    #[arg(
        long,
        value_enum,
        default_value_t = OutputFormat::Human,
        global = true
    )]
    format: OutputFormat,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Detect a local file by content signature.
    Detect {
        source: PathBuf,
        #[arg(long, default_value_t = 67_108_864)]
        max_source_bytes: u64,
        #[arg(long, default_value = "10s", value_parser = parse_duration)]
        timeout: Duration,
    },
    /// Recursively inspect a local file under explicit budgets.
    Inspect {
        source: PathBuf,
        #[command(flatten)]
        budgets: BudgetArgs,
    },
    /// List the direct children of a referenced archive node.
    List {
        source: PathBuf,
        #[arg(value_name = "ARTIFACT_REF")]
        reference: String,
        #[command(flatten)]
        budgets: BudgetArgs,
    },
    /// Read a referenced entry as bounded base64.
    Read {
        source: PathBuf,
        #[arg(value_name = "ARTIFACT_REF")]
        reference: String,
        #[arg(long, default_value_t = 65_536)]
        max_bytes: u64,
        #[command(flatten)]
        budgets: BudgetArgs,
    },
    /// Describe the built-in format adapters and their capabilities.
    Adapters,
    /// Emit the compact contract or a complete JSON Schema document.
    Schema {
        #[arg(long, value_enum, default_value_t = SchemaDocument::Brief)]
        document: SchemaDocument,
    },
    /// Generate a shell completion script.
    Completions { shell: Shell },
}

#[derive(Debug, Clone, Args)]
struct BudgetArgs {
    #[arg(
        long,
        default_value_t = 2,
        help = "Maximum traversal depth or reference steps from the root"
    )]
    depth: u8,
    #[arg(
        long,
        default_value_t = 200,
        help = "Maximum archive entries examined, including reference resolution"
    )]
    max_entries: u64,
    #[arg(long, default_value_t = 67_108_864)]
    max_source_bytes: u64,
    #[arg(long, default_value_t = 67_108_864)]
    max_decompressed_bytes: u64,
    #[arg(long, default_value_t = 100)]
    max_compression_ratio: u64,
    #[arg(long, default_value_t = 2_097_152)]
    max_output_bytes: u64,
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    timeout: Duration,
}

impl BudgetArgs {
    fn limits(&self) -> BudgetLimits {
        BudgetLimits {
            max_depth: self.depth,
            max_entries: self.max_entries,
            max_source_bytes: self.max_source_bytes,
            max_decompressed_bytes: self.max_decompressed_bytes,
            max_compression_ratio: self.max_compression_ratio,
            max_output_bytes: self.max_output_bytes,
            timeout_ms: u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Ndjson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SchemaDocument {
    Brief,
    Detect,
    Inspect,
    List,
    Read,
    Adapters,
    Error,
}

#[must_use]
pub fn run() -> i32 {
    let cli = Cli::parse();
    match execute(cli) {
        Ok(()) => 0,
        Err((error, format)) => {
            render_error(&error, format);
            error.exit_code()
        }
    }
}

fn execute(cli: Cli) -> Result<(), (BlobError, OutputFormat)> {
    let format = cli.format;
    let result = match cli.command {
        Command::Detect {
            source,
            max_source_bytes,
            timeout,
        } => detect_source(
            &source,
            max_source_bytes,
            u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        )
        .and_then(|result| {
            let human = format!(
                "{}: {} ({}, {} bytes)\n{}",
                safe_text(&result.source),
                result.detection.format.as_str(),
                result.detection.media_type,
                result.size,
                result.digest
            );
            emit(&result, format, &human)
        }),
        Command::Inspect { source, budgets } => {
            let options = InspectOptions {
                limits: budgets.limits(),
            };
            inspect_source(&source, &options).and_then(|result| {
                let human = render_inspect_human(&result);
                emit(&result, format, &human)
            })
        }
        Command::List {
            source,
            reference,
            budgets,
        } => {
            let options = InspectOptions {
                limits: budgets.limits(),
            };
            list_reference(&source, &reference, &options).and_then(|result| {
                let human = render_list_human(&result);
                emit(&result, format, &human)
            })
        }
        Command::Read {
            source,
            reference,
            max_bytes,
            budgets,
        } => {
            let options = ReadOptions {
                limits: budgets.limits(),
                max_bytes,
            };
            read_reference(&source, &reference, &options).and_then(|result| {
                let human = format!(
                    "{}\nreturned {}/{} bytes; encoding={}; truncated={}\n{}",
                    safe_text(&result.reference),
                    result.returned_bytes,
                    result.total_bytes,
                    result.encoding,
                    result.truncated,
                    result.data
                );
                emit(&result, format, &human)
            })
        }
        Command::Adapters => {
            let result = adapters();
            let human = result
                .adapters
                .iter()
                .map(|adapter| {
                    format!(
                        "{}\t{}\t{}\t{}",
                        adapter.name,
                        adapter.mode,
                        adapter.formats.join(","),
                        adapter.isolation
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            emit(&result, format, &human)
        }
        Command::Schema { document } => {
            let value = schema_document(document);
            let human = serde_json::to_string_pretty(&value)
                .map_err(|error| (BlobError::Archive(error.to_string()), format))?;
            emit(&value, format, &human)
        }
        Command::Completions { shell } => {
            let mut command = Cli::command();
            clap_complete::generate(shell, &mut command, "blobdive", &mut io::stdout());
            Ok(())
        }
    };
    result.map_err(|error| (error, format))
}

fn emit(value: &impl Serialize, format: OutputFormat, human: &str) -> Result<(), BlobError> {
    let mut stdout = io::stdout().lock();
    match format {
        OutputFormat::Human => writeln!(stdout, "{human}")?,
        OutputFormat::Json => serde_json::to_writer_pretty(&mut stdout, value)
            .map_err(|error| BlobError::Archive(error.to_string()))?,
        OutputFormat::Ndjson => serde_json::to_writer(&mut stdout, value)
            .map_err(|error| BlobError::Archive(error.to_string()))?,
    }
    if format != OutputFormat::Human {
        writeln!(stdout)?;
    }
    Ok(())
}

fn render_error(error: &BlobError, format: OutputFormat) {
    let envelope = error.envelope();
    let mut stderr = io::stderr().lock();
    match format {
        OutputFormat::Human => {
            let _ = writeln!(stderr, "error: {}", safe_text(&error.to_string()));
        }
        OutputFormat::Json => {
            let _ = serde_json::to_writer_pretty(&mut stderr, &envelope);
            let _ = writeln!(stderr);
        }
        OutputFormat::Ndjson => {
            let _ = serde_json::to_writer(&mut stderr, &envelope);
            let _ = writeln!(stderr);
        }
    }
}

fn render_inspect_human(result: &InspectResult) -> String {
    let mut lines = vec![format!(
        "{} ({} bytes read, {} bytes decompressed)",
        safe_text(&result.source),
        result.usage.source_bytes,
        result.usage.decompressed_bytes
    )];
    render_node(&result.root, 0, &mut lines);
    lines.join("\n")
}

fn render_list_human(result: &ListResult) -> String {
    let mut lines = vec![format!("{}:", safe_text(&result.reference))];
    for child in &result.children {
        render_node(child, 1, &mut lines);
    }
    if result.truncation.truncated {
        lines.push(format!("truncated: {:?}", result.truncation.reasons));
    }
    lines.join("\n")
}

fn render_node(node: &ArtifactNode, depth: usize, lines: &mut Vec<String>) {
    let indent = "  ".repeat(depth);
    let truncated = if node.truncation.truncated {
        format!(" truncated={:?}", node.truncation.reasons)
    } else {
        String::new()
    };
    lines.push(format!(
        "{indent}{} [{}; {} bytes]{}",
        safe_text(&node.display_name),
        node.format.as_str(),
        node.size.unwrap_or_default(),
        truncated
    ));
    for finding in &node.findings {
        lines.push(format!(
            "{indent}  ! {}: {}",
            safe_text(&finding.code),
            safe_text(&finding.message)
        ));
    }
    for child in &node.children {
        render_node(child, depth + 1, lines);
    }
}

fn schema_document(document: SchemaDocument) -> Value {
    match document {
        SchemaDocument::Brief => serde_json::to_value(brief_contract()).unwrap_or(Value::Null),
        SchemaDocument::Detect => schema_value::<DetectResult>(),
        SchemaDocument::Inspect => schema_value::<InspectResult>(),
        SchemaDocument::List => schema_value::<ListResult>(),
        SchemaDocument::Read => schema_value::<ReadResult>(),
        SchemaDocument::Adapters => schema_value::<AdaptersResult>(),
        SchemaDocument::Error => schema_value::<ErrorEnvelope>(),
    }
}

fn schema_value<T: schemars::JsonSchema>() -> Value {
    serde_json::to_value(schema_for!(T)).unwrap_or(Value::Null)
}

fn brief_contract() -> BriefContract {
    let mut exit_codes = BTreeMap::new();
    exit_codes.insert("0".to_owned(), "success".to_owned());
    exit_codes.insert("1".to_owned(), "operational failure".to_owned());
    exit_codes.insert("2".to_owned(), "usage error".to_owned());
    exit_codes.insert("3".to_owned(), "resource budget exceeded".to_owned());
    exit_codes.insert("4".to_owned(), "artifact reference not found".to_owned());
    exit_codes.insert(
        "5".to_owned(),
        "source/reference integrity mismatch".to_owned(),
    );

    let mut security = BTreeMap::new();
    security.insert(
        "mutation".to_owned(),
        "input artifacts are never written or materialized".to_owned(),
    );
    security.insert(
        "execution".to_owned(),
        "artifact content is never executed".to_owned(),
    );
    security.insert(
        "parser_isolation".to_owned(),
        "0.1 adapters are in-process and cooperatively bounded; process isolation is not claimed"
            .to_owned(),
    );

    BriefContract {
        schema_version: "blobdive.brief.v1".to_owned(),
        blobdive_version: VERSION.to_owned(),
        commands: [
            "detect",
            "inspect",
            "list",
            "read",
            "adapters",
            "schema",
            "completions",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        output_formats: ["human", "json", "ndjson"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        reference_syntax: "artifact://sha256:<root-digest>!/<adapter>/<entry-index>".to_owned(),
        archive_adapters: ["zip", "tar", "gzip"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        detection_only_formats: [
            "elf", "mach_o", "pe", "pdf", "sqlite", "png", "jpeg", "gif", "webp", "tiff", "flac",
            "wav", "mp3", "mp4", "text", "unknown",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        budget_fields: [
            "depth",
            "max_entries",
            "max_source_bytes",
            "max_decompressed_bytes",
            "max_compression_ratio",
            "max_output_bytes",
            "timeout",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        exit_codes,
        security,
    }
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    humantime::parse_duration(value).map_err(|error| error.to_string())
}

fn safe_text(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}
