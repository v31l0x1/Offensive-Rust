A repository for learning Malware Development in Rust.

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
