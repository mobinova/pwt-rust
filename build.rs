fn main() {
    prost_build::Config::new()
        .compile_protos(&["proto/pwt.proto"], &["proto"])
        .expect("failed to compile pwt.proto");
}
