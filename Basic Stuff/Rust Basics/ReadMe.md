## Running Rust Code

### Method 1: Direct Compilation
```sh
rustc hello.rs
```

### Method 2: Using Cargo
```sh
cargo new helloworld
cd helloworld 
cargo run
```

### Building Rust Binaries
```sh
cargo build

# For release build
cargo build --release
```

### Installing Toolchain
```sh
# View installed target toolchains
rustup show

# View available toolchains we can install
rustup target list

# Install toolchain
rustup install stable-i686-pc-windows-gnu

# Set toolchain as default
rustup default stable-i686-pc-windows-gnu
```

## Rust Basics

### Variables
- Variables are memory locations that store values.
- Values can be integers, floats, characters, or floating point numbers.
- `let` is the predefined keyword to declare a variable.
    ```rust
    let v1 = 100;
    ```

#### Integer Types
- **Signed Integer**: Can take both positive and negative values. The leftmost significant bit indicates the sign.
    ```rust
    let v1: i32 = 100;
    let v2: i32 = -100;
    ```
- **Unsigned Integer**: Can only take positive values (cannot be negative).
    ```rust
    let v2: u32 = 100;
    ```

#### Mutability
- In Rust, variables are **immutable by default**, which means their values cannot be changed.
- To make a variable mutable, use the `mut` keyword during declaration.
    ```rust
    let mut v1 = 100;
    v1 = v1 + 200;
    println!("{}", v1);
    ```

#### Integer Sizes
- **Unsigned**: `u8`, `u16`, `u32`, `u64`, `u128`
- **Signed**: `i8`, `i16`, `i32`, `i64`, `i128`

#### Floating Point Types
```rust
let f1: f32 = 3.141;
let f2: f64 = 3.14159265359;
```

#### Character Type
```rust
let init: char = 'T';
```

#### Shadowing
- Shadowing in Rust allows you to declare a new variable with the same name as a previous variable.
- The second value takes precedence.
    ```rust
    let v1 = 100;
    let v1 = 200; // This value is used
    println!("Value of v1: {}", v1);
    ```

#### Scope
- Scope in Rust is declared between `{ }`.
    ```rust
    let v1 = 100;
    {
        let v1 = 50;
        println!("Value of v1 inside scope: {}", v1);
    }
    println!("Value of v1 outside scope: {}", v1);
    ```

#### Boolean Type
```rust
let flag = true;
let is_active: bool = false;
println!("Flag value: {}", flag);
```

### Operations
- Operations in Rust include:
  - **Arithmetic**: Addition (`+`), Subtraction (`-`), Multiplication (`*`), Division (`/`), Modulo (`%`)
  - **Bitwise**: OR (`|`), AND (`&`), NOT (`!`)
  - **Comparison**: Greater than (`>`), Less than (`<`), Equal to (`==`), Greater than or equal (`>=`), Less than or equal (`<=`)
    ```rust
    let a = 100;
    let b = 50;
    let c = 25;

    let mut d = 0;

    d = a + b;
    d = a - b;
    // Shorthand notation
    d *= 100; // d = d * 100
    d /= 100; // d = d / 100

    println!("{}", a | b);
    println!("{}", a & b);
    println!("{}", !b);
    println!("{}", a > b);
    println!("{}", a < b);
    println!("{}", a == b);
    println!("{}", a <= b);
    println!("{}", a >= b);
    ```
### Loops

#### For Loops
```rust
// Right side value is not inclusive
for i in 1..100 {
    println!("i: {}", i);
}

// To include the right side value, use one of these:
for i in 1..=100 {
    println!("i: {}", i);
}

for i in 1..101 {
    println!("i: {}", i);
}
```

#### While Loop
```rust
let mut i = 0;
while i < 101 {
    println!("i value: {}", i);
    i += 1;
}
```

#### Loop (Infinite Loop)
- The `loop` keyword creates an infinite loop that continues until explicitly broken.
```rust
let mut i = 0;
loop {
    if i == 100 {
        break;
    }
    
    println!("{}", i);
    i += 1;
}
```
### Conditions

#### If-Else Statement
```rust
if a > b {
    println!("A is greater than B");
} else {
    println!("B is greater than A");
}
```

#### If-Else If-Else Statement
```rust
if a > b {
    println!("a is greater than b");
} else if a == b {
    println!("a is equal to b");
} else {
    println!("b is greater than a");
}
```

### Arrays
- Arrays are fixed size collections. You cannot add or remove elements, and the size must be known at compile time.

#### Declaring Arrays
```rust
let arr: [u8; 5] = [5, 6, 7, 8, 9];
let arr2 = [1; 5]; // Creates [1, 1, 1, 1, 1]
```

#### Accessing Array Elements
```rust
let l: [u8; 5] = [5, 6, 7, 8, 9];

// Direct indexing (unsafe - panics if out of bounds)
println!("{}", l[0]);

// Safe access using get()
let res = l.get(2);
match res {
    Some(value) => println!("Value: {}", value),
    None => println!("Index out of bounds"),
}
```

#### Iterating Over Arrays
```rust
let l: [u8; 5] = [5, 6, 7, 8, 9];

// Using for loop with iterator
for item in l.iter() {
    println!("{}", item);
}

// Modifying array elements
let mut l1: [u8; 5] = [1, 2, 3, 4, 5];
for item in l1.iter_mut() {
    *item = *item + 100;
    println!("Modified: {}", item);
}
```

#### Working with Pointers (Unsafe)
```rust
let l: [u8; 5] = [5, 6, 7, 8, 9];
println!("Pointer: {:#?}", l.as_ptr());

unsafe {
    // Read first element via pointer
    let temp = std::ptr::read(l.as_ptr() as *const u8);
    println!("First element: {}", temp);
}
```
### Vectors
- Vectors are dynamic arrays that can grow or shrink in size at runtime.
- A vector contains three parts: **address**, **length**, and **capacity**.
  - **Address**: Points to the starting element
  - **Length**: The number of elements currently in the vector
  - **Capacity**: The total number of elements the vector can store before reallocation
- When adding elements using `push()`, if capacity is reached, the vector reallocates to a larger memory region and copies all elements.

#### Creating Vectors
```rust
// Using vec! macro
let v1: Vec<i32> = vec![2, 3, 6, 8, 9];

// Using Vec::new()
let mut v2: Vec<i32> = Vec::new();
v2.push(10);
v2.push(20);

// With initial capacity
let v3: Vec<i32> = Vec::with_capacity(10);

println!("Vector: {:#?}", v1);
println!("Length: {}, Capacity: {}", v1.len(), v1.capacity());
```
### Strings

#### String Slices (`&str`)
- String slices are immutable references to string data.
- String literals are of type `&str`.
```rust
let name = "laptop"; // Type: &str

// Iterating over characters
for ch in name.chars() {
    println!("{}", ch);
}
```

#### String Type (`String`)
- `String` is a growable, heap-allocated string type.
- Internally, `String` is a vector of bytes (`Vec<u8>`).

#### Converting Between String Types
```rust
let name = "laptop"; // Type: &str

// Method 1: Using String::from()
let myname: String = String::from(name);
println!("String: {}", myname);

// Method 2: Using to_string()
let myname2 = name.to_string();
println!("String: {}", myname2);

// Method 3: Creating mutable String
let mut s = String::new();
s.push_str("Hello");
s.push(' ');
s.push_str("World");
println!("{}", s);
```
### Ownership
- Ownership is Rust's most unique feature that enables memory safety without a garbage collector.
- Each value in Rust has a single owner.
- When the owner goes out of scope, the value is dropped (memory is freed).

#### Ownership Rules
1. Each value in Rust has a variable that's called its **owner**.
2. There can only be **one owner** at a time.
3. When the owner goes **out of scope**, the value is **dropped**.

#### Example: Move Semantics
```rust
let s1 = String::from("hello");
let s2 = s1; // Ownership moved to s2

// println!("{}", s1); // ERROR: s1 is no longer valid
println!("{}", s2); // This works
```

#### Example: Copy Trait
```rust
// Types that implement Copy trait (like integers) are copied, not moved
let x = 5;
let y = x;

println!("x: {}, y: {}", x, y); // Both are valid
```

#### Ownership and Functions
```rust
fn main() {
    let s = String::from("hello");
    takes_ownership(s); // s is moved into the function
    // println!("{}", s); // ERROR: s is no longer valid

    let x = 5;
    makes_copy(x); // x is copied
    println!("{}", x); // x is still valid
}

fn takes_ownership(some_string: String) {
    println!("{}", some_string);
} // some_string is dropped here

fn makes_copy(some_integer: i32) {
    println!("{}", some_integer);
}
```

#### Returning Ownership
```rust
fn main() {
    let s1 = gives_ownership(); // Function returns and moves ownership
    let s2 = String::from("hello");
    let s3 = takes_and_gives_back(s2); // s2 is moved in, then returned
}

fn gives_ownership() -> String {
    let some_string = String::from("yours");
    some_string // Ownership is moved out
}

fn takes_and_gives_back(a_string: String) -> String {
    a_string // Ownership is returned
}
```

### References
- References allow you to refer to a value without taking ownership of it.
- Created using the `&` operator.
- References are immutable by default.

#### Immutable References
```rust
fn main() {
    let s1 = String::from("hello");
    let len = calculate_length(&s1); // Pass a reference
    
    println!("The length of '{}' is {}.", s1, len); // s1 is still valid
}

fn calculate_length(s: &String) -> usize {
    s.len()
} // s goes out of scope, but it doesn't have ownership, so nothing is dropped
```

#### Mutable References
```rust
fn main() {
    let mut s = String::from("hello");
    change(&mut s); // Pass a mutable reference
    println!("{}", s); // Prints "hello, world"
}

fn change(some_string: &mut String) {
    some_string.push_str(", world");
}
```

#### Rules for References
1. At any given time, you can have **either**:
   - One mutable reference, **OR**
   - Any number of immutable references
2. References must always be **valid** (no dangling references).

#### Multiple References Example
```rust
let mut s = String::from("hello");

let r1 = &s; // No problem
let r2 = &s; // No problem
println!("{} and {}", r1, r2);

// let r3 = &mut s; // ERROR: Cannot have mutable reference while immutable refs exist

let r3 = &mut s; // This works after r1 and r2 are no longer used
```

### Borrowing
- Borrowing is the action of creating a reference to a value.
- When you borrow a value, you don't take ownership of it.
- The borrowing rules ensure memory safety at compile time.

#### Immutable Borrowing
```rust
fn main() {
    let s = String::from("hello");
    
    // Multiple immutable borrows are allowed
    let r1 = &s;
    let r2 = &s;
    let r3 = &s;
    
    println!("{}, {}, {}", r1, r2, r3);
}
```

#### Mutable Borrowing
```rust
fn main() {
    let mut s = String::from("hello");
    
    // Only one mutable borrow at a time
    let r1 = &mut s;
    r1.push_str(" world");
    println!("{}", r1);
    
    // Cannot have another mutable borrow while r1 is in scope
    // let r2 = &mut s; // ERROR
}
```

#### Borrowing Rules Prevent Data Races
```rust
fn main() {
    let mut s = String::from("hello");
    
    {
        let r1 = &mut s;
        r1.push_str(" world");
    } // r1 goes out of scope here
    
    // Now we can create another mutable reference
    let r2 = &mut s;
    r2.push_str("!");
    println!("{}", r2);
}
```

#### Dangling References (Prevented by Rust)
```rust
// This code will NOT compile
fn dangle() -> &String { // ERROR: Missing lifetime specifier
    let s = String::from("hello");
    &s // Trying to return reference to s
} // s goes out of scope and is dropped

// Correct approach: Return the String itself
fn no_dangle() -> String {
    let s = String::from("hello");
    s // Ownership is moved out
}
```

#### Practical Example: Borrowing in Functions
```rust
fn main() {
    let mut text = String::from("Hello");
    
    // Immutable borrow
    print_string(&text);
    
    // Mutable borrow
    append_exclamation(&mut text);
    
    println!("{}", text); // Prints "Hello!"
}

fn print_string(s: &String) {
    println!("{}", s);
}

fn append_exclamation(s: &mut String) {
    s.push('!');
}
```
### Functions
```rust
fn main() {
    print_hello();
    print_values(10, 20, 30);
}

fn print_hello() {
    println!("Hello, world!");
}

fn print_values(a: i32, b: i32, c: i32){
    println!("Values are: {}, {}, {}", a, b, c);
}
```