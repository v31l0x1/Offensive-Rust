fn main() {

    let a = 6;
    let b = &a; // or let b = a;

    // a += 4; // creates error if b is a reference

    println!("a: {}",a);
    println!("b: {}",*b);

    let mut s:String = String::from("hello");

    // creates error since s is moved to s1
    // let s1 = s;

    let s1 = &s; // borrow s, the value of s1 doesn't exist after s goes out of scope
    writing(&mut s); // borrow s as mutable reference
    // s.push_str(" world");
    println!("s: {}",s);

    // drop(s);
    // println!("s1: {}",s1);

}


fn writing(name: &mut String) {
    name.push_str(" world");
}

// dangling reference example
// fn test() -> &String {
//     let myname = String::from("hello");
//     return &myname; // myname goes out of scope here, so the reference is dangling
// }