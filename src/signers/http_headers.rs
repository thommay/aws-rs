header! {
    (AmzDate, "X-Amz-Date") => [String]

    // Annoyingly, the tm! macro isn't exported: https://github.com/hyperium/hyper/pull/515
    // test_amz_date {
    //     test_header!(test1, "20110909T233600Z");
    // }
}

header! {
    (Authorization, "Authorization") => [String]

    // test_auth_header {
    //     test_header!(test1, "AWS4-HMAC-SHA256 Credential=akid/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c")
    // }
}
