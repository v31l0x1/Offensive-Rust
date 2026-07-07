fn main() {

    let mut a = 4;
    let mut b:[i32;3] = [1,2,3];

    unsafe {
        let p = &a as *const i32; // pointer can only read
        // println!("Pointer value {}", *p);
        println!("Pointer value: {:x?}", p);
        println!("Pointer address: {:x?}", std::ptr::addr_of!(p));

        let p1 = &mut a as *mut i32; // convert to mutable pointer
        *p1 += 2; // modify value through mutable pointer
        println!("{}", *p1);

        let p2 = b.as_mut_ptr();
        println!("{}", *p2);
    }

    println!("{}", a);
}
