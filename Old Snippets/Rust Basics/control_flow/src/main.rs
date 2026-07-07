fn main() {

    // let one = 1 ;

    // if one > 0 {
    //     println!("True");
    // } else {
    //     println!("False");
    // }

    // loop {
    //     println!("Looping...");
    // }

    // let mut num = 0;
    // 'counter: loop {
    //     println!("Counter: {}", num);
    //     let mut decrease = 5;
    //     loop {
    //         println!("Decrease: {}", decrease);
    //         if decrease == 4 {
    //             break;
    //         }
    //         if num == 2 {
    //             break 'counter;
    //         }
    //         decrease -= 1;
    //     }
    //     num += 1;
    // }

    // let mut num = 0;
    // while num < 5 {
    //     println!("Number: {}", num);
    //     num += 1;
    // }

    // let vec = vec![1, 2, 3, 4, 5];
    // for element in vec {
    //     println!("Element: {}", element);
    // }

    // for number in (1..4).rev() {
    //     println!("{}", number);
    // }

    // let val1 = 5;
    // let val2 = 2;
    // let ans;

    // ans = val1 % val2;
    // println!("{}", ans);

    // let mut vec = vec![2, 4, 6, 8, 10];
    // println!("{:?}", vec);   

    // vec.remove(4);
    // // println!("{:?}", vec);
    
    // vec.push(12);
    // println!("{:?}", vec);

    let message = "Hello";
    let result = concat_string(message);
    println!("{}", result);

    control_flow(10);

}  

fn concat_string(message: &str) -> String {
    message.to_string() + " World"
}

fn control_flow(num: i32) {

    if num == 1 {
        println!("The value is one");
    } else if num < 25 {
        println!("The value is less than 25");
    } else if num > 50 {
        println!("The value is greater than 50");
    } else {
        println!("The value is greater than 25 but less than 50");
    }
}
