#![allow(clippy::tests_outside_test_module, clippy::unwrap_used, reason = "This is an integration test.")]

// In download.hbs we link to some static files hosted by someone else. these must always be live -
// otherwise we want to fail the test suite so we know to update the files.
// Simple regression test.
#[tokio::test]
async fn test_that_static_urls_resolve() {
    let links = vec![
        "https://cdn.jsdelivr.net/npm/simple-icons/icons/linkedin.svg",
        "https://cdn.jsdelivr.net/npm/simple-icons/icons/github.svg"
    ];

    let client = reqwest::Client::new();
    for link in links {
        let link: reqwest::Url = link.parse().unwrap();
        let response = client.get(link.clone()).send().await.unwrap();
        assert_eq!(response.status(), 200);

        // snapshot using insta
        let bytes = response.text().await.unwrap();
        insta::assert_snapshot!(
            format!("{}-{}", link.host_str().unwrap(), link.path_segments().unwrap().last().unwrap()),
            bytes
        );
    }
}
