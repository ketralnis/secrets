// I'm built by build.rs (specified in Cargo.toml) out of api.rs.in

// include the generated output of api.rs.in
include!(concat!(env!("OUT_DIR"), "/api.rs"));
