use readyset_errors::{ReadySetError, ReadySetResult, unsupported};
use readyset_sql::analysis::visit_mut::VisitorMut;
use readyset_sql::ast::{Expr, FieldDefinitionExpr, SelectStatement, SqlQuery};

/// Visitor that traverses a `SelectStatement` and errors if `ROW` is found in the projection.
struct DisallowRowVisitor;

impl<'ast> VisitorMut<'ast> for DisallowRowVisitor {
    type Error = ReadySetError;

    fn visit_select_statement(
        &mut self,
        stmt: &'ast mut SelectStatement,
    ) -> Result<(), Self::Error> {
        for item in &stmt.fields {
            if let FieldDefinitionExpr::Expr {
                expr: Expr::Row { .. },
                ..
            } = item
            {
                unsupported!("ROW constructor not allowed in select");
            }
        }
        Ok(())
    }
}

/// This is a temporary rule that throws an error if it sees the `ROW` constructor (implicit or
/// explicit) in the projection. Row is allowed in other places like predicates; this is only for
/// the projection.
pub trait DisallowRow {
    /// Checks if the `ROW` constructor is used in the projection of a query and throws an error if found.
    ///
    /// ```sql
    /// SELECT ROW(1, 2, 3) FROM t; -- This will result in an error
    /// ```
    ///
    /// Row is allowed in predicates:
    ///
    /// ```sql
    /// SELECT * FROM t WHERE (id, name) IN ((1, 'foo'), (2, 'bar')); -- This is allowed
    /// ```
    fn disallow_row(&mut self) -> ReadySetResult<&mut Self>
    where
        Self: Sized;
}

impl DisallowRow for SelectStatement {
    fn disallow_row(&mut self) -> ReadySetResult<&mut Self> {
        let () = DisallowRowVisitor.visit_select_statement(self)?;
        Ok(self)
    }
}

impl DisallowRow for SqlQuery {
    fn disallow_row(&mut self) -> ReadySetResult<&mut Self> {
        if let SqlQuery::Select(select) = self {
            select.disallow_row()?;
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use readyset_sql::Dialect;
    use readyset_sql_parsing::parse_query;

    #[test]
    fn test_disallow_row_in_projection() {
        let mut query =
            parse_query(Dialect::PostgreSQL, "SELECT ROW(1, 2, 3) FROM things;").unwrap();
        assert!(query.disallow_row().is_err());
    }

    #[test]
    fn test_allow_row_elsewhere() {
        let mut query = parse_query(
            Dialect::MySQL,
            "SELECT * FROM things WHERE (id, name) IN ((1, 'foo'), (2, 'bar'));",
        )
        .unwrap();
        assert!(query.disallow_row().is_ok());

        let mut query = parse_query(
            Dialect::PostgreSQL,
            "SELECT * FROM things WHERE (id, name) IN ((1, 'foo'), (2, 'bar'));",
        )
        .unwrap();
        assert!(query.disallow_row().is_ok());
    }
}
