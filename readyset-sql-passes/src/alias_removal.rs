use std::collections::HashMap;
use std::mem;

use itertools::Itertools;
use readyset_errors::ReadySetResult;
use readyset_sql::analysis::visit_mut::{self, walk_select_statement, VisitorMut};
use readyset_sql::ast::{
    Column, CommonTableExpr, JoinRightSide, Relation, SelectStatement, SqlIdentifier, SqlQuery,
    TableExpr, TableExprInner,
};

#[derive(Debug, PartialEq, Eq)]
pub enum TableAliasRewrite {
    /// An alias to a base table was rewritten
    Table {
        from: SqlIdentifier,
        to_table: Relation,
    },

    /// An alias to a view was rewritten
    View {
        from: SqlIdentifier,
        to_view: Relation,
        for_table: Relation,
    },

    /// An alias to a common table expression was rewritten
    Cte {
        from: SqlIdentifier,
        to_view: Relation,
        for_statement: Box<SelectStatement>, // box for perf
    },
}

pub trait AliasRemoval: Sized {
    /// Remove all table aliases, leaving tables unaliased if possible but rewriting the table name
    /// to a new view name derived from 'query_name' when necessary (ie when a single table is
    /// referenced by more than one alias). Return a list of the rewrites performed.
    fn rewrite_table_aliases(
        self,
        query_name: &str,
        rewrites: Option<&mut Vec<TableAliasRewrite>>,
    ) -> ReadySetResult<Self>;
}

struct RemoveAliasesVisitor<'a> {
    query_name: &'a str,
    table_remap: HashMap<SqlIdentifier, Relation>,
    col_table_remap: HashMap<SqlIdentifier, Relation>,
    out: Vec<TableAliasRewrite>,
}

impl<'ast> VisitorMut<'ast> for RemoveAliasesVisitor<'_> {
    type Error = std::convert::Infallible;

    fn visit_select_statement(
        &mut self,
        select_statement: &'ast mut SelectStatement,
    ) -> Result<(), Self::Error> {
        // Identify the unique table references for every table appearing in the query FROM and
        // JOIN clauses, and group by table name. Both None (ie unaliased) and Some(alias)
        // reference types are included.
        let table_refs = select_statement
            .tables
            .iter()
            .cloned()
            .chain(select_statement.join.iter().flat_map(|j| match j.right {
                JoinRightSide::Table(ref table) => vec![table.clone()],
                JoinRightSide::Tables(ref ts) => ts.clone(),
            }))
            .filter_map(|t| Some((t.inner.try_into_table().ok()?, t.alias)))
            .unique()
            .into_group_map();

        // Use the map of unique table references to identify any necessary alias rewrites.
        let table_alias_rewrites: Vec<TableAliasRewrite> =
            table_refs
                .into_iter()
                .flat_map(|(table, aliases)| match aliases[..] {
                    [None] => {
                        // The table is never referred to by an alias. No rewrite is needed.
                        vec![]
                    }

                    [Some(ref alias)] => {
                        // The table is only ever referred to using one specific alias. Rewrite
                        // to remove the alias and refer to the table itself.
                        vec![TableAliasRewrite::Table {
                            from: alias.clone(),
                            to_table: table,
                        }]
                    }

                    _ => aliases
                        .into_iter()
                        .flatten()
                        .map(|alias| {
                            // The alias is one among multiple distinct references to the
                            // table. Create a globally unique view name, derived from the
                            // query name, and rewrite to remove the alias and refer to this
                            // view.
                            TableAliasRewrite::View {
                                from: alias.clone(),
                                to_view: format!("__{}__{}", self.query_name, alias).into(),
                                for_table: table.clone(),
                            }
                        })
                        .collect(),
                })
                .chain(select_statement.ctes.drain(..).map(
                    |CommonTableExpr { name, statement }| TableAliasRewrite::Cte {
                        to_view: format!("__{}__{}", self.query_name, name).into(),
                        from: name,
                        for_statement: Box::new(statement),
                    },
                ))
                .collect();

        // Extract remappings for FROM and JOIN table references from the alias rewrites.
        let new_table_remap = self
            .table_remap
            .clone()
            .into_iter()
            .chain(table_alias_rewrites.iter().filter_map(|r| match r {
                TableAliasRewrite::View { from, to_view, .. } => {
                    Some((from.clone(), to_view.clone()))
                }
                _ => None,
            }))
            .collect();
        let orig_table_remap = mem::replace(&mut self.table_remap, new_table_remap);

        // Extract remappings for column tables from the alias rewrites.
        let new_col_table_remap = self
            .col_table_remap
            .clone()
            .into_iter()
            .chain(table_alias_rewrites.iter().map(|r| match r {
                TableAliasRewrite::Table { from, to_table } => (from.clone(), to_table.clone()),
                TableAliasRewrite::View { from, to_view, .. } => (from.clone(), to_view.clone()),
                TableAliasRewrite::Cte { from, to_view, .. } => (from.clone(), to_view.clone()),
            }))
            .collect();
        let orig_col_table_remap = mem::replace(&mut self.col_table_remap, new_col_table_remap);

        walk_select_statement(self, select_statement)?;

        self.table_remap = orig_table_remap;
        self.col_table_remap = orig_col_table_remap;

        self.out.extend(table_alias_rewrites);

        Ok(())
    }

    fn visit_table_expr(&mut self, table_expr: &'ast mut TableExpr) -> Result<(), Self::Error> {
        if let Some(table) = table_expr
            .alias
            .as_ref()
            .and_then(|t| self.table_remap.get(t))
            .cloned()
        {
            table_expr.inner = TableExprInner::Table(table);
        } else if let TableExprInner::Table(orig_table @ Relation { schema: None, .. }) =
            &table_expr.inner
        {
            if let Some(table) = self.col_table_remap.get(&orig_table.name) {
                // No schema, but table name in `col_table_remap`, means we're referencing an
                // aliased subquery or CTE
                table_expr.inner = TableExprInner::Table(table.clone());
            }
        }

        if !matches!(&table_expr.inner, TableExprInner::Subquery(_)) {
            table_expr.alias = None;
        }

        visit_mut::walk_table_expr(self, table_expr)
    }

    fn visit_column(&mut self, column: &'ast mut Column) -> Result<(), Self::Error> {
        if let Some(remapped_table) = column
            .table
            .as_ref()
            .and_then(|t| self.col_table_remap.get(&t.name))
            .cloned()
        {
            // We know this table exists
            if let Some(t) = &mut column.table {
                *t = remapped_table;
            }
        }

        Ok(())
    }
}

impl AliasRemoval for SelectStatement {
    fn rewrite_table_aliases(
        mut self,
        query_name: &str,
        rewrites: Option<&mut Vec<TableAliasRewrite>>,
    ) -> ReadySetResult<Self> {
        let mut visitor = RemoveAliasesVisitor {
            query_name,
            table_remap: Default::default(),
            col_table_remap: Default::default(),
            out: Default::default(),
        };

        let Ok(_) = visitor.visit_select_statement(&mut self);

        if let Some(rewrites) = rewrites {
            rewrites.extend(visitor.out);
        }

        Ok(self)
    }
}

impl AliasRemoval for SqlQuery {
    fn rewrite_table_aliases(
        self,
        query_name: &str,
        rewrites: Option<&mut Vec<TableAliasRewrite>>,
    ) -> ReadySetResult<Self> {
        if let SqlQuery::Select(sq) = self {
            let s = sq.rewrite_table_aliases(query_name, rewrites)?;
            Ok(SqlQuery::Select(s))
        } else {
            Ok(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use readyset_sql::ast::{
        BinaryOperator, Column, Expr, FieldDefinitionExpr, ItemPlaceholder, JoinClause,
        JoinConstraint, JoinOperator, JoinRightSide, Literal, Relation, SelectStatement, SqlQuery,
        TableExpr, TableExprInner,
    };
    use readyset_sql::{Dialect, DialectDisplay};
    use readyset_sql_parsing::parse_query;

    use super::{AliasRemoval, TableAliasRewrite};

    macro_rules! rewrites_to {
        ($before: expr, $after: expr) => {{
            let res = parse_query(Dialect::MySQL, $before).unwrap();
            let expected = parse_query(Dialect::MySQL, $after).unwrap();
            let res = res.rewrite_table_aliases("query", None).unwrap();
            assert_eq!(
                res,
                expected,
                "\n     expected: {} \n\
                 to rewrite to: {} \n\
                       but got: {}",
                $before,
                // FIXME(REA-2168): Use correct dialect.
                expected.display(readyset_sql::Dialect::MySQL),
                res.display(readyset_sql::Dialect::MySQL),
            );
        }};
    }

    #[test]
    fn it_removes_aliases() {
        let q = SelectStatement {
            tables: vec![TableExpr {
                inner: TableExprInner::Table(Relation {
                    name: "PaperTag".into(),
                    schema: None,
                }),
                alias: Some("t".into()),
            }],
            fields: vec![FieldDefinitionExpr::from(Column::from("t.id"))],
            where_clause: Some(Expr::BinaryOp {
                lhs: Box::new(Expr::Column(Column::from("t.id"))),
                op: BinaryOperator::Equal,
                rhs: Box::new(Expr::Literal(Literal::Placeholder(
                    ItemPlaceholder::QuestionMark,
                ))),
            }),
            ..Default::default()
        };
        let res = SqlQuery::Select(q);
        let mut rewrites = vec![];
        let res = res
            .rewrite_table_aliases("query", Some(&mut rewrites))
            .unwrap();
        // Table alias removed in field list
        match res {
            SqlQuery::Select(tq) => {
                assert_eq!(
                    tq.fields,
                    vec![FieldDefinitionExpr::from(Column::from("PaperTag.id"))]
                );
                assert_eq!(
                    tq.where_clause,
                    Some(Expr::BinaryOp {
                        lhs: Box::new(Expr::Column(Column::from("PaperTag.id"))),
                        op: BinaryOperator::Equal,
                        rhs: Box::new(Expr::Literal(Literal::Placeholder(
                            ItemPlaceholder::QuestionMark
                        ))),
                    })
                );
                assert_eq!(
                    tq.tables,
                    vec![TableExpr {
                        inner: TableExprInner::Table(Relation {
                            schema: None,
                            name: "PaperTag".into(),
                        }),
                        alias: None,
                    }]
                );
            }
            // if we get anything other than a selection query back, something really weird is up
            _ => panic!(),
        }

        assert_eq!(
            rewrites,
            vec![TableAliasRewrite::Table {
                from: "t".into(),
                to_table: "PaperTag".into(),
            }]
        );
    }

    #[test]
    fn it_removes_nested_aliases() {
        use readyset_sql::ast::{BinaryOperator, Expr};

        let col_small = Column {
            name: "count(t.id)".into(),
            table: None,
        };
        let col_full = Column {
            name: "count(t.id)".into(),
            table: None,
        };
        let q = SelectStatement {
            tables: vec![TableExpr {
                inner: TableExprInner::Table(Relation {
                    schema: None,
                    name: "PaperTag".into(),
                }),
                alias: Some("t".into()),
            }],
            fields: vec![FieldDefinitionExpr::from(col_small.clone())],
            where_clause: Some(Expr::BinaryOp {
                op: BinaryOperator::Equal,
                lhs: Box::new(Expr::Column(col_small)),
                rhs: Box::new(Expr::Literal(Literal::Placeholder(
                    ItemPlaceholder::QuestionMark,
                ))),
            }),
            ..Default::default()
        };
        let res = SqlQuery::Select(q);
        let mut rewrites = vec![];
        let res = res
            .rewrite_table_aliases("query", Some(&mut rewrites))
            .unwrap();
        // Table alias removed in field list
        match res {
            SqlQuery::Select(tq) => {
                assert_eq!(tq.fields, vec![FieldDefinitionExpr::from(col_full.clone())]);
                assert_eq!(
                    tq.where_clause,
                    Some(Expr::BinaryOp {
                        op: BinaryOperator::Equal,
                        lhs: Box::new(Expr::Column(col_full)),
                        rhs: Box::new(Expr::Literal(Literal::Placeholder(
                            ItemPlaceholder::QuestionMark
                        ))),
                    })
                );
                assert_eq!(
                    tq.tables,
                    vec![TableExpr {
                        inner: TableExprInner::Table(Relation {
                            schema: None,
                            name: "PaperTag".into(),
                        }),
                        alias: None,
                    }]
                );
            }
            // if we get anything other than a selection query back, something really weird is up
            _ => panic!(),
        }

        assert_eq!(
            rewrites,
            vec![TableAliasRewrite::Table {
                from: "t".into(),
                to_table: "PaperTag".into()
            }]
        );
    }

    #[test]
    fn it_rewrites_duplicate_aliases() {
        let res = parse_query(
            Dialect::MySQL,
            "SELECT t1.id, t2.name FROM tab t1 JOIN tab t2 ON (t1.other = t2.id)",
        )
        .unwrap();
        let mut rewrites = vec![];
        let res = res
            .rewrite_table_aliases("query_name", Some(&mut rewrites))
            .unwrap();
        match res {
            SqlQuery::Select(tq) => {
                assert_eq!(
                    tq.fields,
                    vec![
                        FieldDefinitionExpr::from(Column::from("__query_name__t1.id")),
                        FieldDefinitionExpr::from(Column::from("__query_name__t2.name"))
                    ]
                );
                assert_eq!(
                    tq.tables,
                    vec![TableExpr {
                        inner: TableExprInner::Table(Relation {
                            schema: None,
                            name: "__query_name__t1".into(),
                        }),
                        alias: None,
                    }]
                );
                assert_eq!(
                    tq.join,
                    vec![JoinClause {
                        operator: JoinOperator::Join,
                        right: JoinRightSide::Table(TableExpr {
                            inner: TableExprInner::Table(Relation {
                                schema: None,
                                name: "__query_name__t2".into(),
                            }),
                            alias: None,
                        }),
                        constraint: JoinConstraint::On(Expr::BinaryOp {
                            op: BinaryOperator::Equal,
                            lhs: Box::new(Expr::Column(Column::from("__query_name__t1.other"))),
                            rhs: Box::new(Expr::Column(Column::from("__query_name__t2.id")))
                        })
                    }]
                );
            }
            // if we get anything other than a selection query back, something really weird is up
            _ => panic!(),
        }

        assert_eq!(
            rewrites,
            vec![
                TableAliasRewrite::View {
                    from: "t1".into(),
                    to_view: "__query_name__t1".into(),
                    for_table: "tab".into(),
                },
                TableAliasRewrite::View {
                    from: "t2".into(),
                    to_view: "__query_name__t2".into(),
                    for_table: "tab".into()
                }
            ]
        );
    }

    #[test]
    fn aliases_in_between() {
        rewrites_to!(
            "SELECT id FROM tbl t1 WHERE t1.value BETWEEN 1 AND 6",
            "SELECT id FROM tbl WHERE tbl.value BETWEEN 1 AND 6"
        );
    }

    #[test]
    fn aliases_in_condition_arithmetic() {
        rewrites_to!(
            "SELECT id FROM tbl t1 WHERE t1.x - t1.y > 0",
            "SELECT id FROM tbl WHERE tbl.x - tbl.y > 0"
        );
    }

    #[test]
    fn joined_subquery() {
        rewrites_to!(
            "SELECT
                 u.id, post_count.count
             FROM users u
             JOIN (
                 SELECT p.author_id, count(p.id) AS count
                 FROM posts p
                 GROUP BY p.author_id
             ) post_count
             ON u.id = post_count.author_id",
            "SELECT
                 users.id, post_count.count
             FROM users
             JOIN (
                 SELECT posts.author_id, count(posts.id) AS count
                 FROM posts
                 GROUP BY posts.author_id
             ) post_count
             ON users.id = post_count.author_id"
        )
    }

    #[test]
    fn correlated_subquery() {
        rewrites_to!(
            "SELECT u.id
             FROM users u
             WHERE EXISTS (select p.id from posts p where p.author_id = u.id)",
            "SELECT users.id
             FROM users
             WHERE EXISTS (select posts.id from posts where posts.author_id = users.id)"
        )
    }

    #[test]
    fn cte() {
        let res = parse_query(
            Dialect::MySQL,
            "WITH max_val AS (SELECT max(t1.value) as value FROM t1)
             SELECT t2.name FROM t2 JOIN max_val ON max_val.value = t2.value;",
        )
        .unwrap();
        let expected = parse_query(
            Dialect::MySQL,
            "SELECT t2.name FROM t2 JOIN __query__max_val ON __query__max_val.value = t2.value;",
        )
        .unwrap();
        let mut rewritten = vec![];
        let res = res
            .rewrite_table_aliases("query", Some(&mut rewritten))
            .unwrap();
        assert_eq!(
            rewritten,
            vec![TableAliasRewrite::Cte {
                from: "max_val".into(),
                to_view: "__query__max_val".into(),
                for_statement: match parse_query(
                    Dialect::MySQL,
                    "SELECT max(t1.value) as value FROM t1"
                )
                .unwrap()
                {
                    SqlQuery::Select(stmt) => Box::new(stmt),
                    _ => panic!(),
                }
            }]
        );
        assert_eq!(
            res,
            expected,
            "\n\n   {}\n!= {}",
            // FIXME(REA-2168): Use correct dialect.
            res.display(readyset_sql::Dialect::MySQL),
            expected.display(readyset_sql::Dialect::MySQL)
        );
    }

    #[test]
    fn schemas() {
        rewrites_to!(
            "SELECT t1.x, t2.x FROM schema_1.t AS t1, schema_2.t AS t2;",
            "SELECT schema_1.t.x, schema_2.t.x FROM schema_1.t, schema_2.t;"
        )
    }
}
