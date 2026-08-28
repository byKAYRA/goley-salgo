#[test]
fn exposes_its_single_responsibility() {
    assert_eq!(
        conformance::CRATE_PURPOSE,
        "original-client conformance harness"
    );
}
