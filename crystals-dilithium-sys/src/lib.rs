

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod dilithium2 {
    include!(concat!(env!("OUT_DIR"), "/bindings_dilithium2.rs"));
}
pub mod dilithium3 {
    include!(concat!(env!("OUT_DIR"), "/bindings_dilithium3.rs"));
}
pub mod dilithium5 {
    include!(concat!(env!("OUT_DIR"), "/bindings_dilithium5.rs"));
}

