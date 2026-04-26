// fn main() {
//     // panic!("panicked here");

//     let mut vector = Vec::new();
    
//     vector.push(19);
//     vector.push(20);
//     vector.push(22);

//     vector[10]; // index out of bounds: the len is 3 but the index is 10
// }

use std::fs::File;
use std::io::ErrorKind;
use std::fs::rename;
use std::io::Error;

fn main() {

    // let file = File::open("error.txt").unwrap();
    // let file = File::open("error.txt").expect("Error opening the file!");

    // let file = match file {
    //     Ok(file) => file,
    //     Err(error) => match error.kind() {
    //         ErrorKind::NotFound => match File::create("error.txt") {
    //             Ok(file_created) => file_created,
    //             Err(error) => panic!("Cannot create the file"),
    //         }
    //         _ => panic!("It was some other error kind!")
    //     }
    // };

    let test = open_file();
    test.unwrap();

    rename_file().unwrap();
}

fn open_file() -> Result<File, Error>{
    let file = File::open("error.txt")?;
    Ok(file)
}

fn rename_file() -> Result<(), Error> {
    let file = rename("error.txt", "rename.txt")?;
    Ok(file)
}