fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(feature = "opencl")]
    precompile_opencl();
}

#[cfg(feature = "opencl")]
fn precompile_opencl() {
    use ocl::{
        builders::ProgramBuilder,
        enums::{ProgramInfo, ProgramInfoResult},
        flags::DeviceType,
        Context,
    };
    use std::{env, fs::File, io::Write, path::PathBuf};

    if let ProgramInfoResult::Binaries(binaries) = ProgramBuilder::new()
        .devices(DeviceType::GPU)
        .source(include_str!("src/sha1_prefix_matcher.cl"))
        .cmplr_opt("-Werror")
        .build(&Context::builder().devices(DeviceType::GPU).build().unwrap())
        .unwrap()
        .info(ProgramInfo::Binaries)
        .unwrap()
    {
        assert_eq!(binaries.len(), 1);

        let out_file = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("sha1_prefix_matcher");
        File::create(&out_file)
            .unwrap()
            .write_all(&binaries[0])
            .unwrap();
    } else {
        panic!("unable to retrieve OpenCL binary info")
    }
}
