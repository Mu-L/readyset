use nom::bytes::complete::tag_no_case;
use nom::multi::separated_list1;
use nom_locate::LocatedSpan;
use readyset_sql::{ast::*, Dialect};

use crate::common::ws_sep_comma;
use crate::table::relation;
use crate::whitespace::whitespace1;
use crate::NomSqlResult;

pub fn rename_table(
    dialect: Dialect,
) -> impl Fn(LocatedSpan<&[u8]>) -> NomSqlResult<&[u8], RenameTableStatement> {
    move |i| {
        let (i, _) = tag_no_case("rename")(i)?;
        let (i, _) = whitespace1(i)?;
        let (i, _) = tag_no_case("table")(i)?;
        let (i, _) = whitespace1(i)?;
        let (i, ops) = separated_list1(ws_sep_comma, rename_table_operation(dialect))(i)?;
        Ok((i, RenameTableStatement { ops }))
    }
}

fn rename_table_operation(
    dialect: Dialect,
) -> impl Fn(LocatedSpan<&[u8]>) -> NomSqlResult<&[u8], RenameTableOperation> {
    move |i| {
        let (i, from) = relation(dialect)(i)?;
        let (i, _) = whitespace1(i)?;
        let (i, _) = tag_no_case("to")(i)?;
        let (i, _) = whitespace1(i)?;
        let (i, to) = relation(dialect)(i)?;
        Ok((i, RenameTableOperation { from, to }))
    }
}

#[cfg(test)]
mod tests {
    use readyset_sql::DialectDisplay;

    use super::*;

    mod mysql {
        use super::*;

        #[test]
        fn simple_rename_table() {
            let qstring = b"RENAME TABLE t1 TO t2";
            let res = test_parse!(rename_table(Dialect::MySQL), qstring);
            assert_eq!(
                res,
                RenameTableStatement {
                    ops: vec![RenameTableOperation {
                        from: Relation::from("t1"),
                        to: Relation::from("t2")
                    }]
                }
            );
            assert_eq!(
                res.display(Dialect::MySQL).to_string(),
                "RENAME TABLE `t1` TO `t2`"
            );
        }

        #[test]
        fn escaped_rename_table() {
            let qstring = b"RENAME TABLE `from` TO `to`";
            let res = test_parse!(rename_table(Dialect::MySQL), qstring);
            assert_eq!(
                res,
                RenameTableStatement {
                    ops: vec![RenameTableOperation {
                        from: Relation::from("from"),
                        to: Relation::from("to")
                    }]
                }
            );
            assert_eq!(
                res.display(Dialect::MySQL).to_string(),
                "RENAME TABLE `from` TO `to`"
            );
        }

        #[test]
        fn compound_rename_table() {
            let qstring = b"RENAME TABLE t1 TO t2, `change` to t3, t4 to `select`";
            let res = test_parse!(rename_table(Dialect::MySQL), qstring);
            assert_eq!(
                res,
                RenameTableStatement {
                    ops: vec![
                        RenameTableOperation {
                            from: Relation::from("t1"),
                            to: Relation::from("t2"),
                        },
                        RenameTableOperation {
                            from: Relation::from("change"),
                            to: Relation::from("t3"),
                        },
                        RenameTableOperation {
                            from: Relation::from("t4"),
                            to: Relation::from("select")
                        }
                    ]
                }
            );
            assert_eq!(
                res.display(Dialect::MySQL).to_string(),
                "RENAME TABLE `t1` TO `t2`, `change` TO `t3`, `t4` TO `select`"
            );
        }

        #[test]
        fn flarum_rename_1() {
            let qstring = b"rename table `posts_likes` to `post_likes`";
            let res = test_parse!(rename_table(Dialect::MySQL), qstring);
            assert_eq!(
                res,
                RenameTableStatement {
                    ops: vec![RenameTableOperation {
                        from: Relation::from("posts_likes"),
                        to: Relation::from("post_likes"),
                    }]
                }
            );
            assert_eq!(
                res.display(Dialect::MySQL).to_string(),
                "RENAME TABLE `posts_likes` TO `post_likes`"
            );
        }
    }

    mod postgres {
        use super::*;

        #[test]
        fn simple_rename_table() {
            let qstring = b"RENAME TABLE t1 TO t2";
            let res = test_parse!(rename_table(Dialect::PostgreSQL), qstring);
            assert_eq!(
                res,
                RenameTableStatement {
                    ops: vec![RenameTableOperation {
                        from: Relation::from("t1"),
                        to: Relation::from("t2")
                    }]
                }
            );
            assert_eq!(
                res.display(Dialect::PostgreSQL).to_string(),
                "RENAME TABLE \"t1\" TO \"t2\""
            );
        }

        #[test]
        fn escaped_rename_table() {
            let qstring = b"RENAME TABLE \"from\" TO \"to\"";
            let res = test_parse!(rename_table(Dialect::PostgreSQL), qstring);
            assert_eq!(
                res,
                RenameTableStatement {
                    ops: vec![RenameTableOperation {
                        from: Relation::from("from"),
                        to: Relation::from("to")
                    }]
                }
            );
            assert_eq!(
                res.display(Dialect::PostgreSQL).to_string(),
                "RENAME TABLE \"from\" TO \"to\""
            );
        }

        #[test]
        fn compound_rename_table() {
            let qstring = b"RENAME TABLE t1 TO t2, \"change\" to t3, t4 to \"select\"";
            let res = test_parse!(rename_table(Dialect::PostgreSQL), qstring);
            assert_eq!(
                res,
                RenameTableStatement {
                    ops: vec![
                        RenameTableOperation {
                            from: Relation::from("t1"),
                            to: Relation::from("t2"),
                        },
                        RenameTableOperation {
                            from: Relation::from("change"),
                            to: Relation::from("t3"),
                        },
                        RenameTableOperation {
                            from: Relation::from("t4"),
                            to: Relation::from("select")
                        }
                    ]
                }
            );
            assert_eq!(
                res.display(Dialect::PostgreSQL).to_string(),
                "RENAME TABLE \"t1\" TO \"t2\", \"change\" TO \"t3\", \"t4\" TO \"select\""
            );
        }

        #[test]
        fn flarum_rename_1() {
            let qstring = b"rename table \"posts_likes\" to \"post_likes\"";
            let res = test_parse!(rename_table(Dialect::PostgreSQL), qstring);
            assert_eq!(
                res,
                RenameTableStatement {
                    ops: vec![RenameTableOperation {
                        from: Relation::from("posts_likes"),
                        to: Relation::from("post_likes"),
                    }]
                }
            );
            assert_eq!(
                res.display(Dialect::PostgreSQL).to_string(),
                "RENAME TABLE \"posts_likes\" TO \"post_likes\""
            );
        }
    }
}
