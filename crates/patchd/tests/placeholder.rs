#[test]
fn patchd_declares_patch_and_launcher_roles() {
    assert_eq!(patchd::ENDPOINT_ROLES, ["patch", "launcher"]);
}
