fn main() {
    // Force rerun if manifest changes
    println!("cargo:rerun-if-changed=injector.exe.manifest");
    println!("cargo:rerun-if-changed=injector.rc");
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        println!("cargo:warning=Embedding manifest for UAC elevation...");
        embed_resource::compile("injector.rc", embed_resource::NONE);
        println!("cargo:warning=Manifest embedded successfully");
    }
}
