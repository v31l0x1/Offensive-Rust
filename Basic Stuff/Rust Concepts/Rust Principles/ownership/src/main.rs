fn main() {

    // let x = 2;
    // let y = x; // x is copied to y, both x and y are valid
    // println!("x: {}, y: {}", x, y);
    
    // Move
    // let mut var = Vec::new();
    // var.push(1);
    // var.push(2);
    // let var2 = var;
    // println!("Vector: {:?}", var2);

    // Clone
    // let x = vec!["Hello".to_string()];
    // let y = x.clone();
    // println!("{:?}", x);
    // println!("{:?}", y);

    // Copy
    // let x = 1;
    // let y = x;
    // println!("x: {}, y: {}", x, y);

    // let s = String::from("Hello"); // create a variable with a string value
    // takes_ownership(s); // give ownership of the string to the function

    // println!("s: {}", s); // error: value borrowed here after move


    // let str1: String = gives_ownership(); // gives_ownership moves its return value into st1
    // println!("{}", str1);

    // let str2: String = take_and_give(str1);
    // println!("{}", str2);

    // let s = String::from("Hello");
    // change_reference(&s); // pass a reference to s
    // read_only(&s); // pass a reference to s
    // println!("{}", s);

    // let mut s = "Hello".to_string(); // s is stored on the heap
    // s.push_str(", World");

    let mut vec1 = vec![1, 3, 5, 7];
    println!("{:?}", mod_vector(&vec1));
    vec1.push(15);
    println!("{:?}", vec1);

    let mut num = 2;
    num = add_two(num);
    // add_two(&mut num);
    println!("{}", num);
}

fn check_vec(vec: Vec<i32>) -> bool{
    if vec[0] == 1 {
        return true as bool;
    } else {
        return false as bool;
    }
}

fn add_two(i: i8) -> i8 {
    i + 2
}

// fn add_two(i :&mut i8) {
//     *i += 2;
// }

fn mod_vector(vec: &Vec<i32>) -> bool {

    if vec[0] == 1 {
        return true as bool;
    } else {
        return false as bool;
    }
}

// fn read_only(s: &String) {
//     println!("String: {}", s);
// }

// fn change_reference(s: &mut String) {
//     s.push_str(", World"); // error: cannot borrow `s` as mutable, as it is not declared as mutable
// }

// fn take_and_give(string: String) -> String {
//     string // string is returned and moves out to the calling function
// }

// fn gives_ownership() -> String {
//     "Gives onwership".to_string()
// }

// fn takes_ownership(string: String) {
//     let in_str = string;
//     println!("String: {}", in_str);
// }

// x is dropped, s is dropped 
