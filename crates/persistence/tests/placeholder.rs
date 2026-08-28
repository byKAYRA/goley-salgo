#[test]
fn exposes_its_single_responsibility() {
    assert_eq!(persistence::CRATE_PURPOSE, "Goley persistence boundary");
}
