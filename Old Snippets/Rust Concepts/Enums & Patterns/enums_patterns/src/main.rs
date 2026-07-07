// enum Pet {
//     Dog,
//     Cat,
//     Fish
// }

// enum IpAddrEnum {
//     V4(String),
//     V6
// }

// struct IpAddr {
//     kind:IpAddrEnum,
//     address: String
// }

// impl Pet {
//     fn what_am_i(self) -> &'static str {
//         match self {
//             Pet::Dog => "I am a dog",
//             Pet::Cat => "I am a cat",
//             Pet::Fish => "I am a fish"
//         }
//     }
// }

enum Shape {
    Triangle,
    Square,
    Pentagon,
    Octagon
}

impl Shape {
    fn corners(self) -> i8 {
        match self {
            Shape::Triangle => 3,
            Shape::Square => 4,
            Shape::Pentagon => 5,
            Shape::Octagon => 8,
        }
    }
}

fn main() {

    let shape = Shape::Triangle;

    let corners = shape.corners();
    println!("{:?}", corners);

    // let dog = Pet::Dog;
    // println!("{}", dog.what_am_i());

    // let test = IpAddrEnum::V4(String::from("127.0.0.1"));

    // let home = IpAddr {
    //     kind: IpAddrEnum::V6,
    //     address: String::from("127.0.0.1")
    // }; 

    // let some_numer = Some(5);
    // let some_string = Some(String::from("Some String"));
    // let nothing: Option<i32> = None; 

    // let five = Some(5);
    // let six = plus_one(five);
    // println!("{:?}", six);

    // what_pet("Dog");

    // let dog = Some(Pet::Dog);
    // if let Some(Pet::Dog) = dog {
    //     println!("The animal is a dog")
    // } else {
    //     println!("The animal is not a dog")
    // }

    // let mut stack = vec![1, 2, 3, 4];

    // while let Some(top) = stack.pop() {
    //     println!("{}", top);
    // }

    // let x = 5; 
    
    // match x {
    //     5 | 6 => println!("This number is 5 or 6"),
    //     _ => println!("The number is not 5 or 6")
    // }

    // match x {
    //     1..10 => println!("Matches"),
    //     _ => println!("Not Matching")
    // }
    
    // let x = Some(5);
    // let y = 5;

    // match x {
    //     Some(10) => println!("10"),
    //     Some(x) if x == y =>println!("Matches!"),
    //     _ => println!("default!")
    // }
}

// fn what_pet(input: &str) {
//     match input {
//         "Dog" => println!("I am a dog"),
//         "Cat" => println!("I am a Cat"),
//         "Fish" => println!("I am a Fish"),
//         _ => println!("I have no clue what pet you have")
//     }
// }

// fn plus_one(x: Option<i32>) -> Option<i32> {
//     match x {
//         None => None,
//         Some(i) => Some(i + 1)
//     }
// }

// enum Option<T> {
//     None,
//     Some(T)
// }