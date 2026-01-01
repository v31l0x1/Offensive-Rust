fn main() {
    
    // signed integer
    let mut v1 = 100;

    v1 = v1 + 200;
    // unsigned integer
    let v2:u32 = 200;

    let v3:f32 = 10.5;

    let v4:char = 'T';

    println!("v1:{}v2:{}\nv3:{}\nv4:{}", v1, v2, v3,v4);

    println!("Size of v1: {}", std::mem::size_of_val(&v1));

    {
        let v1 = 50;
        println!("v1 value inside scope: {}", v1);
    }
    println!("v1 value outside scope: {}", v1);
}