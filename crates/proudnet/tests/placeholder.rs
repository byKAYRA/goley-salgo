#[test]
fn exposes_its_single_responsibility() {
    assert_eq!(proudnet::CRATE_PURPOSE, "standalone ProudNet transport");
}
