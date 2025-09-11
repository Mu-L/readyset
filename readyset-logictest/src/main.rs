use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Display};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use antithesis_sdk::prelude::*;
use anyhow::{anyhow, Context};
use clap::Parser;
use console::style;
use database_utils::{DatabaseType, DatabaseURL};
use futures::stream::futures_unordered::FuturesUnordered;
use futures::StreamExt;
use lazy_static::lazy_static;
use proptest::prelude::any_with;
use proptest::strategy::Strategy;
use proptest::test_runner::{self, TestCaseError, TestError, TestRng, TestRunner};
use query_generator::{QueryOperationArgs, QuerySeed};
use readyset_client::consensus::AuthorityType;
use readyset_sql_parsing::ParsingPreset;
use readyset_tracing::init_test_logging;
use serde_json::json;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use walkdir::WalkDir;

pub mod ast;
pub mod from_query_log;
pub mod generate;
pub mod parser;
pub mod permute;
pub mod runner;

// readyset_alloc initializes the global allocator
extern crate readyset_alloc;

use crate::from_query_log::FromQueryLog;
use crate::generate::Generate;
use crate::permute::Permute;
use crate::runner::{NoriaOptions, RunOptions, TestScript};

const REPORT_HANG: Duration = Duration::from_secs(20 * 60);

#[derive(Parser)]
struct Opts {
    #[command(subcommand)]
    subcommand: Command,
}

#[derive(Parser)]
#[allow(clippy::large_enum_variant)]
enum Command {
    Parse(Parse),
    Verify(Verify),
    Generate(Generate),
    FromQueryLog(FromQueryLog),
    Fuzz(Fuzz),
    Permute(Permute),
}

impl Command {
    fn run(self) -> anyhow::Result<()> {
        match self {
            Self::Parse(parse) => parse.run(),
            Self::Verify(verify) => verify.run(),
            Self::Generate(generate) => generate.run(),
            Self::FromQueryLog(convert) => convert.run(),
            Self::Fuzz(fuzz) => {
                // This will live as long as the program anyway, and we need to be able to reference
                // it from multiple different async tasks, so we can just leak a reference, which is
                // cheaper than putting it in an Arc or something
                let fuzz: &'static mut _ = Box::leak(Box::new(fuzz));
                fuzz.run()
            }
            Self::Permute(permute) => permute.run(),
        }
    }
}

#[derive(Parser)]
struct InputFileOptions {
    /// Files or directories containing test scripts to run. If `-`, will read from standard input
    ///
    /// Any files whose name ends in `.fail.test` will be run, but will be expected to *fail* for
    /// some reason - if any of them pass, the overall run will fail (and noria-logictest will exit
    /// with a non-zero status code)
    paths: Vec<PathBuf>,

    /// Load input files from subdirectories of the given paths recursively
    #[arg(long, short = 'r')]
    recursive: bool,
}

/// The set of input files we are going to run over
#[derive(Default)]
struct InputFiles {
    /// The files we expect to pass
    expected_passes: Vec<(PathBuf, Box<dyn io::Read>)>,

    /// The files we expect to fail
    expected_failures: Vec<(PathBuf, Box<dyn io::Read>)>,
}

impl TryFrom<&'_ InputFileOptions> for InputFiles {
    type Error = anyhow::Error;

    fn try_from(opts: &InputFileOptions) -> Result<Self, Self::Error> {
        if opts.paths == vec![Path::new("-")] {
            Ok(InputFiles {
                expected_passes: vec![("stdin".to_string().into(), Box::new(io::stdin()))],
                ..Default::default()
            })
        } else {
            let (expected_failures, expected_passes) = opts
                .paths
                .iter()
                .map(
                    |path| -> anyhow::Result<Vec<(PathBuf, Box<dyn io::Read>)>> {
                        if path.is_file() {
                            Ok(vec![(path.to_path_buf(), Box::new(File::open(path)?))])
                        } else if path.is_dir() {
                            let mut walker = WalkDir::new(path);
                            if !opts.recursive {
                                walker = walker.max_depth(1);
                            }

                            walker
                                .into_iter()
                                .filter(|e| e.as_ref().map_or(true, |e| e.file_type().is_file()))
                                .map(|entry| -> anyhow::Result<(PathBuf, Box<dyn io::Read>)> {
                                    let entry = entry?;
                                    let path = entry.path();
                                    Ok((path.to_owned(), Box::new(File::open(path)?)))
                                })
                                .collect()
                        } else {
                            Err(anyhow!(
                                "Invalid path {}, must be a filename, directory, or `-`",
                                path.to_str().unwrap()
                            ))
                        }
                    },
                )
                .collect::<anyhow::Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .partition(|(name, _)| name.to_string_lossy().as_ref().ends_with(".fail.test"));

            Ok(InputFiles {
                expected_passes,
                expected_failures,
            })
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum ExpectedResult {
    Pass,
    Fail,
}

impl Display for ExpectedResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExpectedResult::Pass => write!(f, "pass"),
            ExpectedResult::Fail => write!(f, "fail"),
        }
    }
}

struct InputFile {
    name: PathBuf,
    data: Box<dyn io::Read>,
    expected_result: ExpectedResult,
}

impl IntoIterator for InputFiles {
    type Item = InputFile;

    type IntoIter = Box<dyn Iterator<Item = InputFile>>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(
            self.expected_passes
                .into_iter()
                .map(|(name, data)| InputFile {
                    name,
                    data,
                    expected_result: ExpectedResult::Pass,
                })
                .chain(
                    self.expected_failures
                        .into_iter()
                        .map(|(name, data)| InputFile {
                            name,
                            data,
                            expected_result: ExpectedResult::Fail,
                        }),
                ),
        )
    }
}

/// Test the parser on one or more sqllogictest files
#[derive(Parser)]
struct Parse {
    #[command(flatten)]
    input_opts: InputFileOptions,

    /// Output the resulting parsed records after parsing
    #[arg(short, long)]
    output: bool,
}

impl Parse {
    pub fn run(&self) -> anyhow::Result<()> {
        for InputFile { name, data, .. } in InputFiles::try_from(&self.input_opts)? {
            let filename = name.canonicalize()?;
            info!(?filename, "parsing records");
            match parser::read_records(data) {
                Ok(records) => {
                    info!(count = records.len(), "Successfully parsed records",);
                    if self.output {
                        println!("{records:#?}");
                    }
                }
                Err(err) => error!(?filename, ?err, "Error parsing records"),
            };
        }
        Ok(())
    }
}

/// Run a test script, or all test scripts in a directory, against either ReadySet or a reference
/// upstream database
#[derive(Parser)]
struct Verify {
    #[command(flatten)]
    input_opts: InputFileOptions,

    /// If passed, connect to and run verification against the database with the given URL, which
    /// should start with either postgresql:// or mysql://, rather than using an in-process Readyset
    /// instance.
    #[arg(long, conflicts_with_all = ["readyset_url", "mysql", "postgresql"])]
    database_url: Option<DatabaseURL>,

    /// If passed, connect to and run verification against the remote Readyset instance.
    #[arg(long, conflicts_with_all = ["database_url", "mysql", "postgresql"])]
    readyset_url: Option<DatabaseURL>,

    /// Shorthand for `--database-url mysql://root:noria@localhost:3306/sqllogictest`
    #[arg(long, conflicts_with_all = ["database_url", "readyset_url", "postgresql"])]
    mysql: bool,

    /// Shorthand for `--database-url postgresql://postgres:noria@localhost:5432/sqllogictest`
    #[arg(long, conflicts_with_all = ["database_url", "readyset_url", "mysql"])]
    postgresql: bool,

    /// Enable an upstream database backend for the client, with replication to ReadySet.  All
    /// writes will pass through to the given database and be replicated to ReadySet.
    ///
    /// The value should be a database URL starting with either postgresql:// or mysql://
    ///
    /// Only relevant for in-process Readyset instance.
    #[arg(long, conflicts_with_all = ["database_url", "readyset_url", "mysql", "postgresql"])]
    replication_url: Option<String>,

    /// The parsing preset to configure Readyset with if using an in-process instance.
    #[arg(
        long,
        env = "PARSING_PRESET",
        value_enum,
        default_value = "both-prefer-nom",
        hide = true,
        conflicts_with_all = ["database_url", "readyset_url", "mysql", "postgresql"],
    )]
    parsing_preset: ParsingPreset,

    /// Type of database to use for the adapter.
    ///
    /// Only relevant for in-process Readyset instance; should match --replication-url if present.
    #[arg(
        long,
        default_value = "mysql",
        value_enum,
        conflicts_with_all = ["database_url", "readyset_url", "mysql", "postgresql"],
    )]
    database_type: DatabaseType,

    /// Enable query graph reuse in Readyset.
    ///
    /// Only relevant for in-process Readyset instance.
    #[arg(long, conflicts_with_all = ["database_url", "readyset_url", "mysql", "postgresql"])]
    enable_reuse: bool,

    /// Number of parallel tasks to use to run tests. Ignored if --binlog-mysql is passed
    #[arg(long, short = 't', default_value = "32", env = "NORIA_LOGICTEST_TASKS")]
    tasks: usize,

    /// When tests are encountered that are expected to fail but do not, rename the test file from
    /// .fail.test to .test
    #[arg(long)]
    rename_passing: bool,

    /// When tests that are expected to pass fail, rename the test file from .test to .fail.test
    #[arg(long)]
    rename_failing: bool,

    /// Collect timing of all named queries
    #[arg(long)]
    time: bool,

    /// Enable verbose log output
    #[arg(long, short = 'v')]
    verbose: bool,

    /// Logging/tracing options
    #[command(flatten)]
    tracing: readyset_tracing::Options,

    /// Authority connection string. This parameter is ignored if
    /// authority is "local".
    // TODO(justin): The default address should depend on the authority
    // value.
    ///
    /// Only relevant for in-process Readyset instance.
    #[arg(
        long,
        short = 'z',
        env = "AUTHORITY_ADDRESS",
        default_value = "",
        conflicts_with_all = ["database_url", "readyset_url", "mysql", "postgresql"],
    )]
    authority_address: String,

    /// The authority to use. Possible values: consul, local.
    #[arg(
        long,
        env = "AUTHORITY",
        default_value = "local",
        value_enum,
        conflicts_with_all = ["database_url", "readyset_url", "mysql", "postgresql"],
    )]
    authority: AuthorityType,
}

#[derive(Default)]
struct VerifyResult {
    pub failures: Vec<String>,
    pub unexpected_passes: Vec<String>,
    pub passes: usize,
}

impl VerifyResult {
    pub fn is_success(&self) -> bool {
        self.failures.is_empty() && self.unexpected_passes.is_empty()
    }
}

impl Display for VerifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n_scripts = |n| format!("{} test script{}", n, if n == 1 { "" } else { "s" });
        if self.passes > 0 {
            writeln!(
                f,
                "{}",
                style(format!("Successfully ran {}\n", n_scripts(self.passes))).green()
            )?;
        }

        if !self.failures.is_empty() {
            writeln!(f, "{} failed:\n", n_scripts(self.failures.len()))?;
            for script in &self.failures {
                writeln!(f, "    {script}")?;
            }
        }

        if !self.unexpected_passes.is_empty() {
            writeln!(
                f,
                "{} {} expected to fail, but did not:\n",
                n_scripts(self.unexpected_passes.len()),
                if self.unexpected_passes.len() == 1 {
                    "was"
                } else {
                    "were"
                }
            )?;
            for script in &self.unexpected_passes {
                writeln!(f, "    {script}")?;
            }
            writeln!(
                f,
                "TIP: To rectify this, copy and paste the following commands in the relevant directory:"
            )?;
            for script in &self.unexpected_passes {
                writeln!(
                    f,
                    "    mv {} {}",
                    script,
                    script.replace(".fail.test", ".test")
                )?;
            }
        }

        Ok(())
    }
}

lazy_static! {
    static ref DEFAULT_MYSQL_URL: DatabaseURL = "mysql://root:noria@localhost:3306/sqllogictest"
        .parse()
        .unwrap();
    static ref DEFAULT_POSTGRESQL_URL: DatabaseURL =
        "postgresql://postgres:noria@localhost:5432/sqllogictest"
            .parse()
            .unwrap();
}

impl Verify {
    fn target_database_url(&self) -> Option<&DatabaseURL> {
        if self.mysql {
            Some(&*DEFAULT_MYSQL_URL)
        } else if self.postgresql {
            Some(&*DEFAULT_POSTGRESQL_URL)
        } else if self.readyset_url.is_some() {
            self.readyset_url.as_ref()
        } else {
            self.database_url.as_ref()
        }
    }

    #[tokio::main]
    async fn run(&self) -> anyhow::Result<()> {
        let result = Arc::new(Mutex::new(VerifyResult::default()));
        let mut tasks = FuturesUnordered::new();

        let max_tasks = if self.replication_url.is_some() {
            // Cannot parallelize tests when replicating because each test reuses the same db
            1
        } else {
            self.tasks
        };

        for InputFile {
            name,
            data,
            expected_result,
        } in InputFiles::try_from(&self.input_opts)?
        {
            let mut script = TestScript::read(name.clone(), data)
                .with_context(|| format!("Reading {}", name.to_string_lossy()))?;
            let run_opts: RunOptions = self.into();
            let result = Arc::clone(&result);
            let rename_passing = self.rename_passing;
            let rename_failing = self.rename_failing;
            let deployment_name = script.name();
            let authority = Arc::new(
                self.authority
                    .to_authority(&self.authority_address, &deployment_name),
            );

            let noria_opts = NoriaOptions { authority };

            tasks.push(tokio::spawn(async move {
                let test_started = Instant::now();

                let script_name = script.name().to_string();
                let hang_notifier = tokio::spawn(async move {
                    tokio::time::sleep(REPORT_HANG).await;
                    info!(
                        script_name,
                        "Test has been running for {REPORT_HANG:?}; it may be stuck"
                    );
                });

                let script_result = script
                    .run(run_opts, noria_opts)
                    .await
                    .with_context(|| format!("Running test script {}", script.name()));

                hang_notifier.abort();

                info!(
                    script_name = %script.name(),
                    operations = script.len(),
                    duration = test_started.elapsed().as_secs_f64(),
                    expected_result = %expected_result,
                    succeeded = %script_result.is_ok(),
                    "script finished",
                );

                match script_result {
                    Ok(_) if expected_result == ExpectedResult::Fail => {
                        result
                            .lock()
                            .await
                            .unexpected_passes
                            .push(script.name().into_owned());

                        let failing_fname = script.path().to_str().unwrap();
                        let passing_fname = failing_fname.replace(".fail.test", ".test");
                        if rename_passing {
                            warn!(script_name = %script.name(), "Renaming {} to {}", failing_fname, passing_fname);
                            fs::rename(Path::new(failing_fname), Path::new(&passing_fname))
                                .unwrap();
                        } else {
                            error!(
                                script_name = %script.name(),
                                "Script {} didn't fail, but was expected to (maybe rename it to {}?)",
                                failing_fname, passing_fname,
                            );
                        }
                    }
                    Err(err) if expected_result == ExpectedResult::Pass => {
                        result
                            .lock()
                            .await
                            .failures
                            .push(script.name().into_owned());
                        let passing_fname = script.path().to_str().unwrap();
                        let failing_fname = passing_fname.replace(".test", ".fail.test");
                        if rename_failing {
                            warn!(script_name = %script.name(), "Renaming {} to {}", passing_fname, failing_fname);
                            fs::rename(Path::new(passing_fname), Path::new(&failing_fname))
                                .unwrap();
                        } else {
                            error!(
                                script_name = %script.name(),
                                ?err,
                                "Script {} failed, but was expected to pass (maybe rename it to {}?)",
                                passing_fname, failing_fname,
                            );
                        }
                    }
                    Err(err) => {
                        info!(
                            script_name = %script.name(),
                            %err,
                            "Test script {} failed as expected",
                            script.name(),
                        );
                        result.lock().await.passes += 1;
                    }
                    _ => {
                        result.lock().await.passes += 1;
                    }
                }
            }));

            if tasks.len() >= max_tasks {
                // We want to limit the number of concurrent tests, so we wait for one of the
                // current tasks to finish first
                tasks.select_next_some().await.unwrap();
            }
        }

        while !tasks.is_empty() {
            tasks.select_next_some().await.unwrap();
        }

        info!(result = %result.lock().await, "verify finished");

        if result.lock().await.is_success() {
            Ok(())
        } else {
            Err(anyhow!("Test run failed"))
        }
    }
}

impl From<&Verify> for RunOptions {
    fn from(verify: &Verify) -> Self {
        Self {
            database_type: verify.database_type,
            enable_reuse: verify.enable_reuse,
            upstream_database_url: verify.target_database_url().cloned(),
            upstream_database_is_readyset: verify.readyset_url.is_some(),
            parsing_preset: verify.parsing_preset,
            replication_url: verify.replication_url.clone(),
            time: verify.time,
            verbose: verify.verbose,
        }
    }
}

/// Representation for a test seed to be passed to proptest
#[derive(Debug, Clone, Copy)]
struct Seed([u8; 32]);

impl Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for Seed {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(hex::decode(s)?.try_into().map_err(|_| {
            anyhow!("Wrong number of bytes for seed, expected 32")
        })?))
    }
}

/// Fuzz-test noria by randomly generating queries and seed data, and ensuring that both ReadySet
/// and a reference database return the same results
#[derive(Parser, Debug, Clone)]
pub struct Fuzz {
    /// Number of test cases to generate
    ///
    /// Each test case consists of a list of queries that will be run against both ReadySet and the
    /// reference database
    #[arg(long, short = 'n', default_value = "100")]
    num_tests: u32,

    /// Maximum number of iterations to run when shrinking test cases
    #[arg(long, default_value = "1024")]
    max_shrink_iters: u32,

    /// Hex-encoded seed for the random generator to use when generating test cases. Defaults to a
    /// randomly generated seed.
    #[arg(long)]
    seed: Option<Seed>,

    /// URL of a reference database to compare to.
    #[arg(long)]
    compare_to: String,

    /// URL of a remote Readyset to test; if absent, an in-process server and adapter will be
    /// started for each test.
    #[arg(long)]
    readyset_url: Option<String>,

    /// Write generated test scripts to this file.
    ///
    /// If not specified, test scripts will be written to a temporary file
    #[arg(long, short = 'o')]
    output: Option<PathBuf>,

    #[arg(
        long,
        env = "PARSING_PRESET",
        value_enum,
        default_value = "both-panic-on-mismatch",
        hide = true
    )]
    parsing_preset: ParsingPreset,
}

impl Fuzz {
    fn run(&'static self) -> anyhow::Result<()> {
        let mut runner = if let Some(Seed(seed)) = self.seed {
            TestRunner::new_with_rng(self.into(), TestRng::from_seed(Default::default(), &seed))
        } else {
            TestRunner::new(self.into())
        };

        let readyset_url = self
            .readyset_url
            .as_ref()
            .map(|url| DatabaseURL::from_str(url).unwrap());

        let result = runner.run(&self.test_script_strategy(), move |mut test_script| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _guard = rt.enter();
            rt.block_on(test_script.run(
                RunOptions {
                    database_type: DatabaseURL::from_str(&self.compare_to)?.database_type(),
                    upstream_database_url: readyset_url.clone(),
                    upstream_database_is_readyset: readyset_url.is_some(),
                    replication_url: Some(self.compare_to.clone()),
                    parsing_preset: self.parsing_preset,
                    ..RunOptions::default_for_database(self.dialect().into())
                },
                Default::default(),
            ))
            .map_err(|err| TestCaseError::fail(format!("{:#}\n{:?}", err.root_cause(), err)))
        });

        let (passed, details) = match result {
            Err(TestError::Fail(reason, script)) => {
                let path = self
                    .output
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("/tmp/readyset-logictest-fuzz.test"));
                let mut file = OpenOptions::new()
                    .truncate(true)
                    .create(true)
                    .write(true)
                    .open(&path)?;
                error!(?path, %reason, "test failed, writing out failing test script");
                script.write_to(&mut file)?;
                file.flush()?;
                let message = reason.message().lines().next().unwrap_or("unknown");
                (
                    false,
                    json!({
                        "failure_kind": "failing_query",
                        "extract_file": path.to_string_lossy(),
                        // Truncate reason (which includes the query) because especially large
                        // queries are useless to log here. The query will be in the file.
                        "reason": message[..256.min(message.len())],
                    }),
                )
            }
            Err(TestError::Abort(reason)) => (
                false,
                json!({
                    "failure_kind": "abort",
                    "reason": reason.message(),
                }),
            ),
            Ok(()) => {
                info!("No failing queries found");
                (true, json!({}))
            }
        };

        assert_always!(passed, "No failing queries found", &details);

        Ok(())
    }

    fn test_script_strategy(&self) -> impl Strategy<Value = TestScript> + 'static {
        let dialect = self.dialect();
        (
            any_with::<Vec<QuerySeed>>((
                (1..=1).into(),
                QueryOperationArgs {
                    dialect: dialect.into(),
                },
            )),
            self.generate_opts(),
        )
            .prop_filter_map(
                "Making test script from seed failed",
                move |(query_seeds, generate_opts)| {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    let _guard = rt.enter();
                    let mut seed = generate::Seed::from_seeds(query_seeds, dialect).unwrap();
                    match rt.block_on(seed.run(generate_opts, dialect)) {
                        Ok(script) => Some(script.clone()),
                        Err(err) => {
                            error!(?err, "Error generating test script from seed");
                            None
                        }
                    }
                },
            )
    }

    fn generate_opts(&self) -> impl Strategy<Value = generate::GenerateOpts> + 'static {
        let compare_to = DatabaseURL::from_str(&self.compare_to).unwrap();
        (0..100usize).prop_flat_map(move |rows_per_table| {
            let compare_to = compare_to.clone();
            (0..=rows_per_table).prop_map(move |rows_to_delete| generate::GenerateOpts {
                compare_to: compare_to.clone(),
                rows_per_table,
                random: true,
                include_deletes: true,
                rows_to_delete: Some(rows_to_delete),
            })
        })
    }

    fn dialect(&self) -> readyset_sql::Dialect {
        match DatabaseURL::from_str(&self.compare_to).unwrap() {
            DatabaseURL::MySQL(_) => readyset_sql::Dialect::MySQL,
            DatabaseURL::PostgreSQL(_) => readyset_sql::Dialect::PostgreSQL,
        }
    }
}

impl<'a> From<&'a Fuzz> for test_runner::Config {
    fn from(fuzz: &'a Fuzz) -> Self {
        Self {
            cases: fuzz.num_tests,
            max_shrink_iters: fuzz.max_shrink_iters,
            ..Default::default()
        }
    }
}

fn main() -> anyhow::Result<()> {
    antithesis_init();
    init_test_logging();
    let opts = Opts::parse();
    opts.subcommand.run()
}
