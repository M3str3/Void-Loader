fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    
    if args.is_empty() {
        println!("Hello, World!");
    } else {
        for name in args {
            println!("Hello, {}!", name);
        }
    }
}