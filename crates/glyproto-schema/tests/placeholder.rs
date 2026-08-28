#[test]
fn canonical_placeholder_schema_exists() {
    assert!(std::path::Path::new(glyproto_schema::ROOT_SCHEMA).is_file());
}
