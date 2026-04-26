// use std::thread;

// fn main() {
//     // let handle = std::thread::spawn( move || {
//     //     println!("Hello from a thread");
//     // });

//     // // thread::sleep(Duration::from_secs(1));

//     // handle.join().unwrap();

//     let vec = vec![13,4,4];

//     // let handle = std::thread::spawn( move || {
//     //     println!("{:?}", vec)
//     // });

//     let mut thread_handles = Vec::new();

//     for e in vec {
//         thread_handles.push(thread::spawn( move || {
//             println!("Thread: {}", e);
//         }));
//     }

//     println!("Main thread");

//     for handle in thread_handles {
//         handle.join().unwrap();
//     }

// }

// use std::sync::mpsc; // Multi producer single consumer

// fn main() {
//     let (transmitter, receiver) = mpsc::channel();

//     let tx = transmitter.clone();

//     // let val = String::from("Transmitting");

//     // std::thread::spawn(move || {
//     //     transmitter.send(val).unwrap();
//     // });

//     // let msg = receiver.recv().unwrap();
//     // println!("Message: {}", msg);

//     std::thread::spawn(move || {
//         let vec = vec![
//             String::from("Transmitting"),
//             String::from("From"),
//             String::from("Original"),
//         ];
//         for val in vec {
//             transmitter.send(val).unwrap();
//         }
//     });

//     std::thread::spawn(move || {
//         let vec = vec![
//             String::from("Clone"),
//             String::from("is"),
//             String::from("Transmitting"),
//         ];
//         for val in vec {
//             tx.send(val).unwrap();
//         }
//     });

//     for rec in receiver {
//         println!("{}", rec);
//     }

// }

// use std::{rc::Rc, sync::Arc};

// fn main() {
//     let rc1 = Arc::new(String::from("Test"));
//     let rc2 = rc1.clone();

//     std::thread::spawn( move || {
//         rc2;
//     });

// }

// use std::sync::{Arc, Mutex};

// fn main() {
//     let counter = Arc::new(Mutex::new(0));
//     let mut handles = vec![];

//     for _ in 0..8 {
//         let counter = Arc::clone(&counter);
//         let handle: std::thread::JoinHandle<()> = std::thread::spawn(move || {
//             let mut num = counter.lock().unwrap();
//             *num += 1;
//         });
//         handles.push(handle);
//     }

//     for handle in handles {
//         handle.join().unwrap();
//     }

//     println!("{:?}", counter.lock().unwrap());
// }

// use std::sync::{Arc, Mutex};


// fn main() {
//     let lock = Arc::new(Mutex::new(0));
//     let lock2 = Arc::clone(&lock);

//     let _ = std::thread::spawn( move || -> () {
//         let _guard = lock2.lock().unwrap(); //we acquire the lock here
//         panic!(); // mutex is poisoned
//     }).join();

//     let mut guard = match lock.lock() {
//         Ok(guard) => guard,
//         Err(poisined) => poisined.into_inner()
//     };

//     *guard += 1;
//     println!("{:?}", guard);
// }

// use rayon::prelude::*;
// use num::{BigUint, One, one};
// use std::time::Instant;


// fn factorial(num: u32) -> BigUint {
//     if num == 0 || num == 1  {
//         return BigUint::one();
//     } else {
//         (1..=num).map(BigUint::from).reduce(|acc, x| acc * x).unwrap()
//     }
// }

// fn multi_fact(num: u32) -> BigUint {
//     if num == 0 || num == 1 {
//         return BigUint::one()
//     } else {
//         (1..=num).into_par_iter().map(BigUint::from).reduce(|| BigUint::one(), |acc, x| acc * x)
//     }
// }

// fn main() {

//     // println!("Factorial: {}", factorial(3));

//     // println!("Factorial: {}", multi_fact(3));

//     let now = Instant::now();
//     factorial(50000);
//     println!("{:.2?}", now.elapsed());

//     let now = Instant::now();
//     multi_fact(50000);
//     println!("{:.2?}", now.elapsed());
// }


use rayon::prelude::*;
use std::time::{Duration, Instant};

fn fib_recursive(n: u32) -> u32 {
    if n < 2 {
        return n;
    }

    fib_recursive(n - 1) + fib_recursive(n - 2)
}

fn fibonacci_join(n: u32) -> u32 {
    if n < 2 {
        return n;
    }

    //Solution to the assignment goes here
    let (a, b) = rayon::join(|| fib_recursive(n-1), || fib_recursive(n - 2));
    a + b
}

fn main() {
    let start = Instant::now();
    let x = fib_recursive(47);
    let duration = start.elapsed();
    println!("Recursive fibonacci answer: {}, time taken: {:?}", x, duration);

    println!("Now run with Rayon's join.");

    let start = Instant::now();
    let x = fibonacci_join(47);
    let duration = start.elapsed();
    println!("Rayon fibonacci answer: {}, time taken: {:?}", x, duration);
}
