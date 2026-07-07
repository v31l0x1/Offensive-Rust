// struct Point<T> {
//     x: T,
//     y: T
// }

// struct Point2<T, U> {
//     x: T,
//     y: U
// }


// fn main() {
//     let cord = Point{x:5.0, y:5.0};
//     let cord = Point {
//         x: String::from("x"),
//         y: String::from("y")
//     };

// }

// use std::fmt::format;



// trait Overview {
//     fn overview(&self) -> String {
//         String::from("This is a Rust course")
//     }
// }

// struct Course {
//     headline: String,
//     author: String
// }

// struct AnotherCourse {
//     headline: String,
//     author: String
// }

// impl Overview for Course {
//     // fn overview(&self) -> String {
//     //     format!("{}, {}", self.headline, self.author)
//     // }
// }

// impl Drop for Course {
//     fn drop(&mut self) {
//         println!("Dropping: {}", self.author);
//     }
// }

// impl Overview for AnotherCourse {
//     fn overview(&self) -> String {
//         format!("{}, {}", self.headline, self.author)
//     }
// }

// fn main() {

//     let course1 = Course{
//         headline: String::from("Headling!"),
//         author: String::from("Author1")
//     };

//     let course2 = AnotherCourse {
//         headline: String::from("Headline"),
//         author: String::from("Author2")
//     };

//     println!("{:?}",course1.overview());

//     println!("{:?}", course2.overview());

//     call_overview(&course1);
//     call_overview(&course2);

//     call_gen(&course1);

//     drop(course1);

// }

// fn call_overview(item: &impl Overview) {
//     println!("Overview: {}", item.overview());
// }

// fn call_gen<T: Overview>(item: &T) {
//     println!("Overview: {}", item.overview());
// }

// fn call_overview(item1: &impl Overview, item2: &impl Overview)
// fn call_overview<T: Overview>(item1: &T, item2: &T)
// fn call_overview(item: &impl Overview + AnotherTrait)
// fn overview<T: Overview + AnotherTrait>(item1: &T, item2: &T)


// trait Clone: Sized {
//     fn clone(&self) -> Self;
//     fn clone_from(&mut self, source: &Self) {
//         *self = source.clone()
//     }
// }

/*
use std::ops::Add;
use std::ops::Sub;
*/

// #[derive(Debug)]
// struct Point<T> {
//     x: T,
//     y: T
// }

// impl<T> Sub for Point<T> 
//     where
//     T: Sub<Output = T> {
//         type Output =  Self;
//         fn sub(self, rhs: Self) -> Self::Output {
//             Point {
//                 x: self.x - rhs.x,
//                 y: self.y - rhs.y
//             }
//         }
// }

// impl<T> Add for Point<T>
//     where 
//     T: Add<Output = T> {
//         type Output = Self;
//         fn add(self, rhs: Self) -> Self {
//             Point {
//                 x: self.x + rhs.x,
//                 y: self.y + rhs.y,
//             }
//         }
// }
// fn main() {

//     let cord = Point {
//         x: 5.0,
//         y: 4.0
//     };
//     let cord1 = Point {
//         x: 1.0,
//         y: 2.0
//     };

//     let sum = cord + cord1;
//     println!("{:?}", sum);
//     // let sub = cord - cord1;
//     // println!("{:?}", sub);
// }

use std::fmt::Debug;

trait Upgrade {
    fn set_mpg(&mut self, _input: u32);
    fn set_color(&mut self, _color: String);
    fn set_top_speed(&mut self, _top_speed: u32);
}

#[derive(Debug)]
struct Car {
    mpg: u32,
    color: String,
    top_speed: u32
}

impl Upgrade for Car {
    fn set_mpg(&mut self, mpg: u32) {
        self.mpg = mpg
    }
    fn set_color(&mut self, color: String) {
        self.color = color
    }
    fn set_top_speed(&mut self, top_speed: u32) {
        self.top_speed = top_speed
    }
}

#[derive(Debug)]
struct MotorCycle {
    mpg: u32,
    color: String,
    top_speed: u32
}

impl Upgrade for MotorCycle {
    fn set_mpg(&mut self, mpg: u32) {
        self.mpg = mpg
    }
    fn set_color(&mut self, color: String) {
        self.color = color
    }
    fn set_top_speed(&mut self, top_speed: u32) {
        self.top_speed = top_speed
    }
}

fn main() {
    let mut car = Car {
        mpg: 2,
        color: String::from("Green"),
        top_speed: 20
    };

    let mut motorcycle = MotorCycle {
        mpg: 2,
        color: String::from("Black"),
        top_speed: 100
    };

    println!("{:?}", car);
    println!("{:?}", motorcycle);

    car.set_mpg(10);
    car.set_color(String::from("White"));
    car.set_top_speed(50);
    println!("{:?}", car);

    motorcycle.set_mpg(10);
    motorcycle.set_color(String::from("White"));
    motorcycle.set_top_speed(50);
    println!("{:?}", motorcycle);

    print(String::from("Test"));

}

fn print<T: std::fmt::Debug>(value: T) {
    println!("{:?}", value);
}