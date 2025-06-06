use std::collections::{HashMap, HashSet};
use std::iter;

use itertools::{Either, Itertools};
use readyset_errors::{
    internal_err, invalid_query_err, unsupported, unsupported_err, ReadySetResult,
};
use readyset_sql::ast::{
    BinaryOperator, Column, Expr, FieldDefinitionExpr, JoinConstraint, JoinRightSide, Relation,
    SelectStatement, SqlIdentifier, SqlQuery, TableExpr, TableExprInner,
};

pub trait DetectProblematicSelfJoins: Sized {
    /// Detect and return an unsupported error for any joins where both sides of the join key are
    /// (or could be) based on expressions dependent on the same column in the same table. These
    /// queries return incorrect results due to
    /// [ENG-411](https://readysettech.atlassian.net/browse/ENG-411)
    ///
    /// This must be run after the following rewrite passes:
    /// - [`expand_implied_tables`](super::ImpliedTableExpansion::expand_implied_tables)
    /// - [`expand_stars`](super::StarExpansion::expand_stars)
    fn detect_problematic_self_joins(self) -> ReadySetResult<Self>;
}

fn check_select_statement<'a>(
    stmt: &'a SelectStatement,
    cte_ctx: &HashMap<&'a SqlIdentifier, &'a SelectStatement>,
) -> ReadySetResult<()> {
    // Iterate over all the *base table* columns in the query that the given *projected* column
    // depends on
    fn dependent_columns<'a>(
        col: &'a Column,
        stmt: &'a SelectStatement,
        cte_ctx: &HashMap<&'a SqlIdentifier, &'a SelectStatement>,
    ) -> ReadySetResult<impl Iterator<Item = ReadySetResult<(Relation, &'a str)>> + 'a> {
        let table = col.table.as_ref().ok_or_else(|| {
            internal_err!("detect_problematic_self_joins must be run after expand_implied_tables")
        })?;

        let table_matches = |tbl: &TableExpr| {
            (table.schema.is_none() && tbl.alias.as_ref() == Some(&table.name))
                || matches!(&tbl.inner, TableExprInner::Table(t) if t == table)
        };

        macro_rules! once_ok {
            ($tn: expr, $cn: expr) => {
                once_ok!(($tn, $cn))
            };
            ($col: expr) => {
                Either::Left(iter::once(Ok($col)))
            };
        }

        if let Some(TableExpr {
            inner: TableExprInner::Table(tbl),
            ..
        }) = stmt.tables.iter().find(|t| table_matches(t))
        {
            Ok(once_ok!(tbl.clone(), col.name.as_str()))
        } else {
            let ctes = cte_ctx
                .iter()
                .map(|(k, v)| (*k, *v))
                .chain(stmt.ctes.iter().map(|cte| (&cte.name, &cte.statement)))
                .collect::<HashMap<_, _>>();

            fn trace_subquery<'a>(
                stmt: &'a SelectStatement,
                table: Relation,
                col_name: &'a str,
                ctes: &HashMap<&'a SqlIdentifier, &'a SelectStatement>,
            ) -> ReadySetResult<impl Iterator<Item = ReadySetResult<(Relation, &'a str)>> + 'a>
            {
                check_select_statement(stmt, ctes)?;
                let expr = stmt
                    .fields
                    .iter()
                    .find_map(|field| match field {
                        FieldDefinitionExpr::Expr {
                            expr,
                            alias: Some(alias),
                        } if *alias == col_name => Some(expr),
                        FieldDefinitionExpr::Expr {
                            expr: expr @ Expr::Column(Column { name, .. }),
                            alias: None,
                        } if *name == col_name => Some(expr),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        invalid_query_err!(
                            "Could not resolve column reference {}.{}",
                            table.display_unquoted(),
                            col_name
                        )
                    })?;
                let ctes = ctes.clone();
                Ok(expr
                    .recursive_subexpressions()
                    .chain(iter::once(expr))
                    .map(move |expr| match expr {
                        Expr::Column(col) => {
                            Ok(Either::Left(Box::new(dependent_columns(col, stmt, &ctes)?)
                                as Box<dyn Iterator<Item = Result<_, _>>>))
                        }
                        _ => Ok(Either::Right(iter::empty())),
                    })
                    .flatten_ok()
                    .map(
                        |r: Result<Result<_, _>, _>| -> Result<(Relation, &str), _> {
                            r.and_then(std::convert::identity)
                        },
                    ))
            }

            let mut res = None;
            for te in &stmt.tables {
                if table_matches(te) {
                    match &te.inner {
                        TableExprInner::Table(t) => {
                            res = Some(once_ok!(t.clone(), col.name.as_str()));
                            break;
                        }
                        TableExprInner::Subquery(sq) => {
                            res = Some(Either::Right(trace_subquery(
                                sq.as_ref(),
                                table.clone(),
                                &col.name,
                                &ctes,
                            )?));
                        }
                    }
                    break;
                }
            }
            if res.is_none() {
                for j in &stmt.join {
                    match &j.right {
                        JoinRightSide::Table(
                            te @ TableExpr {
                                inner: TableExprInner::Table(t),
                                ..
                            },
                        ) if table_matches(te) => {
                            res = Some(once_ok!(t.clone(), col.name.as_str()));
                            break;
                        }
                        JoinRightSide::Table(TableExpr {
                            inner: TableExprInner::Subquery(sq),
                            alias: Some(alias),
                        }) if table.schema.is_none() && *alias == table.name => {
                            res = Some(Either::Right(trace_subquery(
                                sq,
                                table.clone(),
                                &col.name,
                                &ctes,
                            )?));
                            break;
                        }
                        JoinRightSide::Tables(ts) => {
                            if let Some(TableExpr {
                                inner: TableExprInner::Table(tbl),
                                ..
                            }) = ts.iter().find(|t| table_matches(t))
                            {
                                res = Some(once_ok!(tbl.clone(), col.name.as_str()));
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }

            Ok(Either::Right(
                res.ok_or_else(|| {
                    unsupported_err!("Could not resolve table alias {}", table.display_unquoted())
                })?
                .map(move |c| {
                    let (tbl, cn) = c?;
                    if let (true, Some(cte)) = (tbl.schema.is_none(), ctes.get(&tbl.name)) {
                        Ok(Either::Right(trace_subquery(cte, tbl, cn, &ctes)?))
                    } else {
                        Ok(once_ok!((tbl, cn)))
                    }
                })
                .flatten_ok()
                .map(|r| r.and_then(std::convert::identity)),
            ))
        }
    }

    fn expr_is_problematic<'a>(
        expr: &'a Expr,
        stmt: &'a SelectStatement,
        cte_ctx: &HashMap<&'a SqlIdentifier, &'a SelectStatement>,
    ) -> ReadySetResult<bool> {
        expr.recursive_subexpressions()
            .chain(iter::once(expr))
            .try_fold(false, |acc, expr| {
                Ok(acc
                    || match expr {
                        Expr::BinaryOp {
                            lhs,
                            op: BinaryOperator::Equal,
                            rhs,
                        } => match (lhs.as_ref(), rhs.as_ref()) {
                            (Expr::Column(lhs), Expr::Column(rhs)) => {
                                let lhs_cols = dependent_columns(lhs, stmt, cte_ctx)?
                                    .collect::<Result<HashSet<_>, _>>()?;
                                let mut problematic = false;
                                for col in dependent_columns(rhs, stmt, cte_ctx)? {
                                    if lhs_cols.contains(&col?) {
                                        problematic = true;
                                        break;
                                    }
                                }
                                problematic
                            }
                            _ => false,
                        },
                        _ => false,
                    })
            })
    }

    for join in &stmt.join {
        match &join.constraint {
            JoinConstraint::Using(_) => unsupported!("USING is unsupported"),
            JoinConstraint::On(expr) => {
                if expr_is_problematic(expr, stmt, cte_ctx)? {
                    unsupported!("Self-joins using the same column are unsupported")
                }
            }
            JoinConstraint::Empty => {}
        }
    }

    Ok(())
}

impl DetectProblematicSelfJoins for SelectStatement {
    fn detect_problematic_self_joins(self) -> ReadySetResult<Self> {
        check_select_statement(&self, &HashMap::new())?;
        Ok(self)
    }
}

impl DetectProblematicSelfJoins for SqlQuery {
    fn detect_problematic_self_joins(self) -> ReadySetResult<Self> {
        match &self {
            SqlQuery::Select(stmt) => {
                check_select_statement(stmt, &HashMap::new())?;
            }
            SqlQuery::CompoundSelect(stmt) => {
                for (_, stmt) in &stmt.selects {
                    check_select_statement(stmt, &HashMap::new())?;
                }
            }
            _ => {}
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod unsupported {
        use readyset_sql::Dialect;
        use readyset_sql_parsing::parse_query;

        use super::*;

        fn is_unsupported(query_str: &str) {
            let query = parse_query(Dialect::MySQL, query_str).unwrap();
            let res = query.detect_problematic_self_joins();
            assert!(res.is_err());
            let err = res.err().unwrap();
            assert!(err.is_unsupported(), "res.err().unwrap() = {err:?}");
        }

        #[test]
        fn easy_case() {
            is_unsupported("SELECT t.x FROM t JOIN t t2 ON t.x = t2.x");
        }

        #[test]
        fn compound_join_key() {
            is_unsupported("SELECT t.x FROM t JOIN t t2 ON t.x = t2.x and t.y = t2.z");
        }

        #[test]
        fn swapped_order() {
            is_unsupported("SELECT t.x, t2.x FROM t JOIN t t2 ON t2.x = t.x");
        }

        #[test]
        fn subquery_with_column() {
            is_unsupported("SELECT t.x FROM t JOIN (select t.x from t) t2 ON t2.x = t.x");
        }

        #[test]
        fn subquery_with_dependent_expression() {
            is_unsupported(
                "SELECT t.x FROM t JOIN (select t.x + 1 - 1 as x from t) t2 ON t2.x = t.x",
            );
        }

        #[test]
        fn subquery_with_join() {
            is_unsupported(
                "SELECT t1.x FROM t1
                   JOIN (SELECT t2.y, t1.x AS x FROM t2 JOIN t1 ON t2.id = t1.id) sq
                     ON t1.x = sq.x",
            );
        }

        #[test]
        fn cte_with_column() {
            is_unsupported(
                "WITH t2 AS (select t.x from t) SELECT t.x FROM t JOIN  T2 ON t2.x = t.x",
            );
        }

        #[test]
        fn cte_with_dependent_expression() {
            is_unsupported(
                "WITH t2 AS (select t.x + 1 - 1 as x from t) SELECT t.x FROM t JOIN  t2 ON t2.x = t.x",
            );
        }

        #[test]
        fn cte_with_join() {
            is_unsupported(
                "WITH sq AS (SELECT t2.y, t1.x AS x FROM t2 JOIN t1 ON t2.id = t1.id)
                 SELECT t1.x FROM t1 JOIN sq ON t1.x = sq.x",
            );
        }

        #[test]
        fn multiple_ctes() {
            is_unsupported(
                "WITH
                   sq1 AS (SELECT t2.y, t1.x AS x FROM t2 JOIN t1 ON t2.id = t1.id),
                   sq2 AS (SELECT t3.y, sq1.x AS x FROM t3 JOIN sq1 ON t2.id = sq1.id)
                 SELECT t1.x FROM t1 JOIN sq2 ON t1.x = sq2.x",
            );
        }

        #[test]
        fn cte_with_topk() {
            is_unsupported(
                "WITH alias_2 AS (
                     SELECT table_1.column_1 AS alias_1
                     FROM table_1
                     ORDER BY table_1.column_1 ASC
                     LIMIT 10
                 )
                 SELECT table_1.column_1 AS alias_3
                 FROM table_1
                 INNER JOIN alias_2
                 ON (table_1.column_1 = alias_2.alias_1)
                 ORDER BY table_1.column_1 ASC
                 LIMIT 10",
            )
        }
    }

    mod supported {
        use readyset_sql::Dialect;
        use readyset_sql_parsing::parse_query;

        use super::*;

        fn is_supported(query_str: &str) {
            let query = parse_query(Dialect::MySQL, query_str).unwrap();
            let res = query.clone().detect_problematic_self_joins();
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), query);
        }

        #[test]
        fn different_column() {
            is_supported("SELECT * FROM t JOIN t t2 ON t.x = t2.y");
        }

        #[test]
        fn different_table() {
            is_supported("SELECT * FROM t JOIN t2 t2 ON t.x = t2.x");
        }
    }
}
