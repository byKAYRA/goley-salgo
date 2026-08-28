#[test]
fn exposes_its_single_responsibility() {
    assert_eq!(
        domain::CRATE_PURPOSE,
        "network-independent Goley domain logic"
    );
}
