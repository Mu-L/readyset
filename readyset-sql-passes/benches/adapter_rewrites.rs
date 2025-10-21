use criterion::{BatchSize, Bencher, Criterion, black_box, criterion_group, criterion_main};
use readyset_sql::Dialect;
use readyset_sql_parsing::parse_select;
use readyset_sql_passes::adapter_rewrites;

fn auto_parameterize_query(c: &mut Criterion) {
    let run_benchmark = |b: &mut Bencher, src: &str| {
        let q = parse_select(Dialect::MySQL, src).unwrap();
        b.iter_batched(
            || q.clone(),
            |mut q| {
                adapter_rewrites::auto_parameterize_query(&mut q, Vec::new(), false, true);
                black_box(q)
            },
            BatchSize::SmallInput,
        )
    };

    c.benchmark_group("auto_parameterize_query")
        .bench_with_input("trivial", "SELECT * FROM t", run_benchmark)
        .bench_with_input(
            "simple",
            "SELECT customer_id, amount, account_name FROM payment WHERE customer_id = 1",
            run_benchmark,
        )
        .bench_with_input(
            "moderate",
            "SELECT * FROM t \
                 WHERE x = 1 \
                 AND ( \
                    y = 4 \
                    AND ( \
                      z = 5 \
                      AND q = 7 \
                      AND (\
                        x = 80 \
                        AND w = ? \
                        AND xx = 43 \
                        AND yz IN (x + 4 - 8))))",
            run_benchmark,
        );
}

criterion_group!(benches, auto_parameterize_query);
criterion_main!(benches);
