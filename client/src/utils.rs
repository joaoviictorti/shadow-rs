use std::path::Path;


pub fn check_file(file: &String) -> bool {
    let file = Path::new(file);
    file.exists()
}