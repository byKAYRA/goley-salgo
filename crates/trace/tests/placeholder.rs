#[test]
fn exposes_its_single_responsibility() {
    assert_eq!(trace::CRATE_PURPOSE, "protocol trace recording and replay");
}
