// #[derive(Debug)]
// #[allow(dead_code)]
// struct City {
//     city: String,
//     population: u64,
// }

// // fn sort_pop(city: &mut Vec<City>) {
// //     // city.sort();
// //     city.sort_by_key(pop_helper);
// // }

// // fn pop_helper(pop: &City) -> u64 {
// //     pop.population
// // }

// fn sort_pop_closure(pop: &mut Vec<City>) {
//     pop.sort_by_key(|p| p.population);
// }

// fn main() {
//     let a = City {
//         city: String::from("Tokyo"),
//         population: 5000
//     };
//     let b = City {
//         city: String::from("Paris"),
//         population: 1000
//     };
//     let c = City {
//         city: String::from("France"),
//         population: 10000
//     };
//     let d = City {
//         city: String::from("Japan"),
//         population: 2000
//     };
    
//     let mut vec: Vec<City> = vec![a,b,c,d];

//     // sort_pop(&mut vec);
//     sort_pop_closure(&mut vec);
//     println!("{:?}", vec);

//     let add = |x: i32| -> i32 { x + 1 } ;
//     let add_v2 = |x| x + 1;
    
//     add(4);
//     add_v2(10);

//     let example = |x| x;
//     let string = example(String::from("This is a sample String"));
//     // let num = example(10); // throws error since the type is set by the compiler as String.


// }

use std::{result, vec};

#[derive(Debug)]
struct Item {
    name: String
}

#[derive(Debug)]
struct Range {
    start: u32,
    end: u32
}

impl Iterator for Range {
    type Item = u32;
    fn next(&mut self) -> Option<Self::Item> {
        if self.start >= self.end {
            return None;
        }        
        let result = Some(self.start);
        self.start += 1;
        result
    }
}

fn check_inventory(items: Vec<Item>, product: String) -> Vec<Item> {
    items.into_iter().filter(|x| x.name == product).collect()
}

fn main() {
    // Fn, FnMut, FnOnce

    // || drop(v) => FnOnce
    // |args| v.contains(arg) => Fn
    // |args| v.push(arg) => FnMut

    // let y = 5; 
    // let add_y = |x:i32| x + y;
    // let copy = add_y; // this is closure being copied.

    // println!("{}", add_y(copy(10)));

    // mutable variable doesn't implement copy or clone
    // let mut y = 5;
    // let mut add_y = |x:i32| { y += x; y};
    // let mut copy = add_y;
    // println!("{}", add_y(copy(10)));

    // let vec = vec![1,2,3,4];

    // for x in vec.iter() {
    //     println!("{}", x);
    // }

    // let vec2 = vec![12,3,4,5];
    // let mut iter = (&vec2).into_iter();

    // while let Some(v) = iter.next() {
    //     println!("{}", v);
    // }


    // let mut vec: Vec<Item> = Vec::new();
    // vec.push(Item { name: String::from("PineApple") });
    // vec.push(Item { name: String::from("Apple") });
    // vec.push(Item { name: String::from("GreenApple") });

    // let checked = check_inventory(vec, String::from("Apple"));

    // println!("{:?}", checked);

    // let range = Range {
    //     start: 0,
    //     end: 10
    // };
    // for r in range {
    //     println!("{}",r);
    // }

    // let vec: Vec<u32> = range.filter(|x| x %2 == 0).collect();
    // println!("{:?}", vec);

    let vec = vec![1,3,5,7,9];
    let mut result: Vec<i32> = vec.iter().map(|x| x * 10).collect();

    println!("{:?}", result);
}

// pub trait Iterator {
//     type Item;
//     fn next(&mut self) -> Option<Self::Item>;

//     // many different methods
// }