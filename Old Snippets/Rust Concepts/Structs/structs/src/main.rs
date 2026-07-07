// struct User {
//     active: bool,
//     username: String,
//     sign_in_count: u32
// }

// struct Coordinates(i32, i32, i32);

// struct UnitStruct;

// struct Square {
//     width: u32,
//     height: u32,
// }

// impl Square {
//     fn area(&self) -> u32 {
//         self.width * self.height
//     }

//     fn change_width(&mut self, new_width: u32) {
//         self.width = new_width;
//     }
// }

// struct MyString<'a> {
//     text: &'a str
// }

struct Car {
    mpg: u32,
    color: String,
    top_speed: u32
}

impl Car {
    fn set_mpg(&mut self, new_mpg: u32) {
        self.mpg = new_mpg;
    }

    fn set_color(&mut self, new_color: String) {
        self.color = new_color;
    }

    fn set_top_speed(&mut self, new_top_speed: u32) {
        self.top_speed = new_top_speed;
    }
}

fn main() {

    // let myString = String::from("Hello");
    // let x = MyString{text: myString.as_str()};

    // let s: &'static str = "I have a static lifetime";

    // let square1 = Square{width:10, height:10};
    // println!("{}", square1.area());

    // let mut square2 = Square{width: 5, height: 5};

    // square2.change_width(10);
    // println!("{}", square2.width);


    let mut car = Car{mpg:30, color: String::from("Black"), top_speed: 100};
    println!("mpg: {}, Color: {}, Top Speed: {}", car.mpg, car.color, car.top_speed);
    car.set_mpg(50);
    car.set_color(String::from("White"));
    car.set_top_speed(200);
    println!("mpg: {}, Color: {}, Top Speed: {}", car.mpg, car.color, car.top_speed);
    // let r;

    // {
    //     let x = 5;
    //     r = &x;
    // }

    // println!("{}", r);
    
    // let cords = Coordinates(1, 2, 3);
    
    // println!("{} {} {}", cords.0, cords.1, cords.2);

    // let user1 = User{active:true, username: String::from("Abc"), sign_in_count: 0};
    // println!("Username: {}, Active: {}, SignInCount: {}", user1.username, user1.active, user1.sign_in_count);

    // let user2 = build_user(String::from("User2"));
    // println!("Username: {}, Active: {}, SignInCount: {}", user2.username, user2.active, user2.sign_in_count);
}

// fn example<'a, 'b>(x: &'a str, y: &'b str) -> &'a str {
//     x
// }

// fn build_user(username: String) -> User {
//     User {
//         username,
//         active: true,
//         sign_in_count: 1,
//     }
// }