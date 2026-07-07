use std::num::Wrapping;


fn djb2_hash<T: ToString>(input: T) -> u32 {
    let s = input.to_string();
    let mut hash: u32 = 3731;
    
    for byte in s.bytes() {
        hash = (hash << 7).wrapping_add(hash).wrapping_add(byte as u32);
    }

    hash
}

pub fn one_time_hash<T: ToString>(k: T) -> Wrapping<u32> {
    let key = k.to_string();
    let mut hash= Wrapping(0u32);
    for c in key.chars(){
        let tmp = Wrapping(c as u32);
        hash += tmp;
        hash += hash << 7;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    hash
}

fn loselose_hash<T: ToString>(input: T) -> u32 {
    
    let mut hash = 0u32;
    let s = input.to_string();

    for byte in s.bytes() {
        hash = hash.wrapping_add(byte as u32).wrapping_mul(byte as u32 + 2);
    }

    hash
}   

fn rotr32_hash<T: ToString>(input: T) -> u32 {

    let mut hash = 0u32;
    let s = input.to_string();

    for byte in s.bytes() {
        hash = (byte as u32).wrapping_add(hash.rotate_right(5));
    }

    hash
}



fn main() {
    let input = "SomeFunctionName";
    let djb2_hash_value = djb2_hash(input);
    println!("DJB2 Hash value for '{}': 0x{:X}", input, djb2_hash_value);


    let one_time_hash_value = one_time_hash(input);
    println!("One-Time Hash value for '{}': 0x{:X}", input, one_time_hash_value);

    let loselose_hash_value = loselose_hash(input);
    println!("Loselose Hash value for '{}': 0x{:X}", input, loselose_hash_value);

    let rotr32_hash_value = rotr32_hash(input);
    println!("ROTR32 Hash value for '{}': 0x{:X}", input, rotr32_hash_value);

}
