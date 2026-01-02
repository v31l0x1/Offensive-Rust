fn main() {

    let l1:[u8;5] = [1, 2, 3, 4, 5];

    for i in 0..5 {
        println!("Element {}: {}", i, l1[i]);
    }
    // accessing elements using unsafe code
    unsafe {

        // let temp = std::ptr::read((l1.as_ptr() as isize + 2 as isize) as *const [u8;5]);

        let temp = std::ptr::read((l1.as_ptr() as isize + (std::mem::size_of::<u8>()*3) as isize) as *const u8);
        println!("First element using unsafe: {}", temp);
    }
    // traversing an array using len method
    for i in 1..l1.len(){
        println!("Element {}: {}", i, l1[i]);
    }
    // using get method to access elements
    for i in 0..l1.len(){

        let res = l1.get(i);
        match res {
            Some(val) => println!("Element using get: {}", val),
            None => println!("No element found"),
        }
    }

    // using iter to traverse an array
    for i in l1.iter(){
        println!("Element using iter: {}", i);
    }


    // modifying elements in an array
    let mut l2:[i32;5] = [10, 20, 30, 40, 50];

    for i in l2.iter_mut(){
        *i += 5;
        println!("Element after mutation: {}", i);
    }
    // using into_iter to consume the array
    let l = [100, 200, 300, 400, 500];
    for i in l.into_iter(){
        println!("Element using into_iter: {}", i);
    }
    println!("{:#?}", l);

    println!("{}", l.contains(&300));

    // modyfying elements using vectors
    let t = l.iter().map(|x| x + 10).collect::<Vec<i32>>();
    println!("{:#?}", t);


    // Vectors

    let v1:Vec<i32> = vec![2,3,6,8,9];

    let v2:Vec<i32> = Vec::new();

    println!("{:#?}",v1);
    println!("{:#?}",v2);

    let mut v3:Vec<i32> = vec![10,20,30];
    v3.push(40);
    let tmp = v3.pop().unwrap();
    println!("Popped element: {}", tmp);
    println!("{:#?}", v3);

    for i in v3.iter(){
        println!("Element in v3: {}", i);
    }

    for i in v3.clone().into_iter(){
        println!("Element in v3 using clone and into_iter: {}", i);
    }

    let t2 = v3.iter().map(|x| {x*2}).collect::<Vec<i32>>();
    println!("{:#?}", t2);
    println!("{:#?}", v3);
    // can't use v3 after this point as into_iter consumes the vector
    for i in v3.into_iter(){
        println!("Element in v3 using into_iter: {}", i);
    }


    let name = "laptop";

    println!("{}",name);

    let myname:String = String::from(name);
    println!("{}",myname);

    let myname2:String = name.to_string();
    println!("{}",myname2);

    let u:Vec<u32> = vec![65,66,67,68,69];

    println!("{}", String::from_utf8_lossy(&u.iter().map(|&x| x as u8).collect::<Vec<u8>>()));

    u.encode_utf16();
}