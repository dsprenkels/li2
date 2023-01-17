use crate::params::D;

pub(crate) fn power2round(mut a0: i32, a: i32) -> (i32, i32) {
    let a1 = (a + (1 << (D-1)) - 1) >> D;
    a0 = a - (a1 << D);
    (a0, a1)
}

// pub(crate) fn power2round(mut a0: i32, a: i32) -> (i32, i32) {
//     const  HI_MASK: i32 = !((1 << D) - 1);
//     let mut a1 = a + (1 << (D-1)) - 1;
//     a1 >>= D;
//     a0 = a & HI_MASK;
//     (a0, a1)
// }
