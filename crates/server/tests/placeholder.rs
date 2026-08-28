#[test]
fn combined_server_declares_all_three_roles() {
    assert_eq!(goley_server::SERVICE_ROLES, ["entry", "lobby", "battle"]);
}
