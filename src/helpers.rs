#[cfg(test)]
use std::fs::File;
use std::io::Read;

pub fn get_file<S: Into<String>>(filename: S) -> String {
    let filepath = format!("./test/fixtures/{}", filename.into());
    let mut f = File::open(filepath).expect("file not found");

    let mut contents = String::new();
    f.read_to_string(&mut contents)
        .expect("something went wrong reading the file");

    contents
}
