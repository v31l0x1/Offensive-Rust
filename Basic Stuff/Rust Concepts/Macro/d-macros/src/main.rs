
// macro_rules! Average {
//     ( $(,)* ) => ({
//         0.0
//     });

//     ( $($val:expr), + $(,)*) => {{
//         let count = 0usize $(+ { let _ = stringify!($val); 1})*;

//         let sum = 0.0 $(+ $val as f64)*;

//         sum / count as f64
//     }};
// }

// fn main() {
//     println!("{}", Average!());
//     println!("{}", Average!(1.0, 2.0, 3.0));
//     println!("{}", Average!(1,2,3,4,5));
// }

macro_rules! op {
    ($a: expr, $b:expr, $c:expr) => {
        {
            let operation = $c;
            let param1 = $a;
            let param2 = $b;
            let result;
            if operation == 1{
                result = param1 + param2;
            } else if operation == 2 {
                result = param1 - param2;
            } else if operation == 3 {
                result = param1 * param2;
            } else if operation == 4 {
                result = param1 / param2;
            } else if operation == 5 {
                result = param1 % param2
            } else {
                result = -1;
            }
            result
        }
    };
}

fn main() {
    println!("{}", op!(5,2,1));
    println!("{}", op!(5,2,2));
    println!("{}", op!(5,2,3));
    println!("{}", op!(5,2,4));
    println!("{}", op!(5,2,5));
    println!("{}", op!(5,2,6));
}