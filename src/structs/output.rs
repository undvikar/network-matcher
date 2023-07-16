use std::fs::File;

pub struct Config {
    pub quiet: bool,
    pub output_file: Option<(File,char)>
}
