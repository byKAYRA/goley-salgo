#[test]
fn empty_workspace_has_zero_protocol_coverage() {
    let report = gly_cov::empty_report();

    assert_eq!(report.messages, 0);
    assert_eq!(report.verified, 0);
    assert_eq!(
        report.to_string(),
        "Protokol kapsam raporu: 0 mesaj / 0 doğrulanmış"
    );
}
