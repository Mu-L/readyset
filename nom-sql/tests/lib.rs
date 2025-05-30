extern crate nom_sql;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use readyset_sql::Dialect;

fn parse_queryset(dialect: Dialect, queries: Vec<String>) -> (i32, i32) {
    let mut parsed_ok = Vec::new();
    let mut parsed_err = 0;
    for query in queries.iter() {
        println!("Trying to parse '{}': ", &query);
        match nom_sql::parse_query(dialect, query) {
            Ok(_) => {
                println!("ok");
                parsed_ok.push(query);
            }
            Err(_) => {
                println!("failed");
                parsed_err += 1;
            }
        }
    }

    println!("\nParsing failed: {parsed_err} queries");
    println!("Parsed successfully: {} queries", parsed_ok.len());
    println!("\nSuccessfully parsed queries:");
    for q in parsed_ok.iter() {
        println!("{q:?}");
    }

    (parsed_ok.len() as i32, parsed_err)
}

fn test_queries_from_file(dialect: Dialect, f: &Path, name: &str) -> Result<i32, i32> {
    let mut f = File::open(f).unwrap();
    let mut s = String::new();

    // Load queries
    f.read_to_string(&mut s).unwrap();
    let lines: Vec<String> = s
        .lines()
        .filter(|l| {
            !(l.is_empty()
                || l.starts_with('#')
                || l.starts_with("--")
                || l.starts_with("/*") && l.ends_with("*/;"))
        })
        .map(|l| {
            if !(l.ends_with('\n') || l.ends_with(';')) {
                String::from(l) + "\n"
            } else {
                String::from(l)
            }
        })
        .collect();
    println!("\nLoaded {} {} queries", lines.len(), name);

    // Try parsing them all
    let (ok, err) = parse_queryset(dialect, lines);

    if err > 0 {
        return Err(err);
    }
    Ok(ok)
}

fn parse_file(dialect: Dialect, path: &str) -> (i32, i32) {
    let mut f = File::open(Path::new(path)).unwrap();
    let mut s = String::new();

    // Load queries
    f.read_to_string(&mut s).unwrap();
    let lines: Vec<&str> = s
        .lines()
        .map(str::trim)
        .filter(|l| {
            !(l.is_empty()
                || l.starts_with('#')
                || l.starts_with("--")
                || l.starts_with("DROP")
                || l.starts_with("/*") && l.ends_with("*/;"))
        })
        .collect();
    let mut q = String::new();
    let mut queries = Vec::new();
    for l in lines {
        if !l.ends_with(';') {
            q.push_str(l);
        } else {
            // end of query
            q.push_str(l);
            queries.push(q.clone());
            q = String::new();
        }
    }
    println!("Loaded {} table definitions", queries.len());

    // Try parsing them all
    parse_queryset(dialect, queries)
}

#[test]
#[ignore]
fn hotcrp_queries() {
    test_queries_from_file(
        Dialect::MySQL,
        Path::new("tests/hotcrp-queries.txt"),
        "HotCRP",
    )
    .unwrap();
}

#[test]
fn hyrise_test_queries() {
    test_queries_from_file(
        Dialect::MySQL,
        Path::new("tests/hyrise-test-queries.txt"),
        "HyRise",
    )
    .unwrap();
}

#[test]
fn tpcw_test_queries() {
    test_queries_from_file(
        Dialect::MySQL,
        Path::new("tests/tpc-w-queries.txt"),
        "TPC-W",
    )
    .unwrap();
}

#[test]
fn tpcw_test_tables() {
    let res = test_queries_from_file(
        Dialect::MySQL,
        Path::new("tests/tpc-w-tables.txt"),
        "TPC-W tables",
    );
    res.unwrap();
    // There are 10 tables
    assert_eq!(res.unwrap(), 10);
}

#[test]
fn exists_test_queries() {
    let res = test_queries_from_file(
        Dialect::MySQL,
        Path::new("tests/exists-queries.txt"),
        "exists/not-exists queries",
    );
    res.unwrap();
    // There are 4 queries
    assert_eq!(res.unwrap(), 4);
}

#[test]
fn finkelstein82_test_queries() {
    let res = test_queries_from_file(
        Dialect::MySQL,
        Path::new("tests/finkelstein82.txt"),
        "Finkelstein 1982",
    );
    res.unwrap();
    // There are 3 tables and 6 queries
    assert_eq!(res.unwrap(), 9);
}

#[test]
fn hotcrp_schema() {
    let mut f = File::open(Path::new("tests/hotcrp-schema.txt")).unwrap();
    let mut s = String::new();

    // Load queries
    f.read_to_string(&mut s).unwrap();
    let lines: Vec<&str> = s
        .lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty() && !l.starts_with('#') && !l.starts_with("--") && !l.starts_with("DROP")
        })
        .collect();
    let mut q = String::new();
    let mut queries = Vec::new();
    for l in lines {
        // remove inline comments, bah
        let l = match l.find('#') {
            None => l,
            Some(pos) => &l[0..pos - 1],
        };
        if !l.ends_with(';') {
            q.push_str(l);
        } else {
            // end of query
            q.push_str(l);
            queries.push(q.clone());
            q = String::new();
        }
    }
    println!("Loaded {} table definitions", queries.len());

    // Try parsing them all
    let (ok, fail) = parse_queryset(Dialect::MySQL, queries);

    // There are 24 CREATE TABLE queries in the schema
    assert_eq!(ok, 24);
    assert_eq!(fail, 0);
}

#[test]
fn mediawiki_schema() {
    let (ok, fail) = parse_file(Dialect::MySQL, "tests/mediawiki-schema.txt");

    // There are 17 CREATE TABLE queries in the schema
    assert_eq!(ok, 17);
    assert_eq!(fail, 0);
}

#[test]
fn parse_comments() {
    let (ok, fail) = parse_file(Dialect::MySQL, "tests/comments.txt");

    // There are 2 CREATE TABLE queries in the schema
    assert_eq!(ok, 2);
    assert_eq!(fail, 0);
}

#[test]
fn parse_autoincrement() {
    let (ok, fail) = parse_file(Dialect::MySQL, "tests/autoincrement.txt");

    // There is 1 CREATE TABLE queries in the schema
    assert_eq!(ok, 1);
    assert_eq!(fail, 0);
}

#[test]
fn parse_select() {
    let (ok, fail) = parse_file(Dialect::MySQL, "tests/select.txt");
    assert_eq!(fail, 1);
    assert_eq!(ok, 27);
}

#[test]
fn parse_alter_table() {
    let (ok, fail) = parse_file(Dialect::MySQL, "tests/alter-table.txt");
    assert_eq!(fail, 2);
    assert_eq!(ok, 9);
}
