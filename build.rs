//! Protobuf codegen for the hub gRPC service (server + client sides).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/sentinel.proto"], &["proto/"])?;
    println!("cargo:rerun-if-changed=proto/sentinel.proto");
    Ok(())
}
