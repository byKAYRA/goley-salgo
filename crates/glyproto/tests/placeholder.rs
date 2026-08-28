#[test]
fn exposes_its_single_responsibility() {
    assert_eq!(
        glyproto::CRATE_PURPOSE,
        "Goley protocol IDL parser and code generator"
    );
}
