// use rand::{rng, seq::SliceRandom};
// fn main() {
//     let mut num:Vec<i32> = vec![];

//     num.push(3);
//     num.push(4);
//     num.push(5);

//     let pop = num.pop(); //Option<T>, return None or Some(T)

//     println!("{:?}",pop); 

//     let two = num[1]; //copy
//     // &nums[1], creates a reference if copy is not available
//     println!("{:?}", two);

//     let one = num.first(); // return a option<T>, so None if vec is empty, or Some<T> is [0]
//     println!("{:?}", one);

//     // .last
//     // .first_mut and .last_mut, so will borrow mutable refernces.

//     println!("{}", num.len()); // return a value of the length
//     println!("{}", num.is_empty()); // bool

//     num.insert(0, 12);
//     num.insert(3, 13);
//     num.insert(2, 34);

//     println!("{:?}", num);

//     num.remove(3);
//     println!("{:?}", num);

//     num.sort();
//     println!("{:?}", num);

//     // num.shuffle(&mut thread_rng());
//     num.shuffle(&mut rng());
//     println!("{:?}", num);

// }

// use std::collections::BinaryHeap;


// fn main() {
//     let mut bheap: BinaryHeap<i32> = BinaryHeap::new();

//     bheap.push(1);
//     bheap.push(18);
//     bheap.push(20);
//     bheap.push(13);

//     bheap.pop();

//     println!("{:?}", bheap);

//     println!("{:?}", bheap.peek()); // peek is going to return Option<T>, return None if empty, Some(T) otherwise

// }

// use std::collections::HashMap;
// use std::collections::BTreeMap;

// fn main() {
    
//     let mut hashmap = HashMap::new();

//     hashmap.insert(1, 1);
//     hashmap.insert(2, 2);
//     hashmap.insert(3, 1);
//     println!("{:?}", hashmap);
    
//     let old = hashmap.insert(3, 10);
//     println!("{:?}", hashmap);
//     println!("{:?}", old);

//     println!("{:?}", hashmap.contains_key(&3));

//     println!("{:?}", hashmap.get(&2));


//     let removed = hashmap.remove(&1);
//     println!("{:?}", removed);

//     let remove = hashmap.remove_entry(&2);
//     println!("{:?}", remove);


//     hashmap.clear();

//     println!("{:?}", hashmap.is_empty());

//     let mut btree = BTreeMap::new();

//     btree.insert(1, String::from("One"));
//     println!("{:?}", btree);

// }

use std::collections::HashSet;

fn main() {

    let mut hashset = HashSet::new();

    hashset.insert(1);
    hashset.insert(2);
    hashset.insert(3);
    hashset.insert(4);

    for x in hashset.iter() {
        println!("Inter: {}", x);
    }

    hashset.remove(&3);
    println!("{:?}", hashset);

    let mut hashset2 = HashSet::new();

    hashset2.insert(2);
    hashset2.insert(4);
    hashset2.insert(5);
    hashset2.insert(9);

    for x in hashset2.intersection(&hashset) {
        println!("Intersection: {}", x);
    }

    let intersection = &hashset & &hashset2;
    for x in intersection {
        println!("Intersection: {}", x);
    }

    for x in hashset2.union(&hashset) {
        println!("Union: {}", x);
    }

    let union = &hashset | &hashset2;
    for x in union {
        println!("Union: {}", x);
    }

    let diff = &hashset2 - &hashset;
    for x in diff {
        println!("diff: {}", x);
    }
}