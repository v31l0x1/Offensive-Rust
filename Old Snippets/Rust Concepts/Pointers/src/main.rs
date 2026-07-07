// fn main() {
//     let t = (12, "eggs"); // created on the stack
//     let b = Box::new(t); // created on the heap, but b stored on the stack.
//     println!("{:?}", b);

//     // let x = 5;
//     // let y = &x;

//     // assert_eq!(5, *y);

//     let x = 5;
//     let y = Box::new(5);

//     assert_eq!(5, *y);
//     println!("{:?}", y);
// }

// use std::rc::Rc;

// fn main() {
//     let s1 = Rc::new(String::from("Pointer"));
//     let s2 = s1.clone();
//     let s3 = s2.clone();

//     println!("{}, {}, {}", s1, s2, s3);
// }

// use std::cell::RefCell;

// struct Flagger {
//     is_true: RefCell<bool>,
// }

// fn main() {
//     let flag = Flagger {
//         is_true: RefCell::new(true)
//     };
//     // borrow return Ref<T>
//     // borrow_mut return RefMut<T>

//     // let reference = flag.is_true.borrow();
//     // println!("{:?}", reference);

//     let mut mut_ref = flag.is_true.borrow_mut();
//     *mut_ref = false; // dereference first to access inside.
//     println!("{:?}", mut_ref);
// }

// use std::cell::RefCell;
// use std::rc::Rc;

// struct Flagger {
//     is_ture: Rc<RefCell<bool>>,
// }

// fn main() {
//     let flag = Flagger {
//         is_ture: Rc::new(RefCell::new(true)),
//     };
    
//     let reference = Rc::new(flag.is_ture.clone());
//     println!("{:?}", reference);

//     let mut mut_ref = flag.is_ture.borrow_mut();
//     *mut_ref = false;
//     println!("{:?}", mut_ref);
// }

use std::rc::Rc;


fn main() {
    //Question 1: Create a variable on the stack and a variable on the heap. Multiply their values and print out the results.

    let x = 10;
    let y = Box::new(2);
    println!("{}", x * *y);

    //Question 2: Create a variable that holds a String
    let string = String::from("Pointer");

    {
        //Create a reference counting smart pointer that points to the above String.
        let reference = Rc::new(string);
        
        //Print out how many references the smart pointer has.
        println!("{}", Rc::strong_count(&reference));

        //Code block
        {
            //Create another reference counting smart pointer that points to our first smart pointer
            let reference2 = Rc::clone(&reference);
            //Print out how many references each smart pointer has
            println!("{}", Rc::strong_count(&reference2));
        }
        //What value is dropped here?
        //Print out how many references out first smart pointer has
        println!("{}", Rc::strong_count(&reference));

    } //What value is dropped here?
    //Comment out the line below. What do you think will happen when you try to run the program now?
    //println!("rc_value: {}", rc_value);
}
