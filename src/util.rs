use std::path::PathBuf;

pub fn get_airoi_dir() -> PathBuf {
    let mut path = dirs::config_dir().unwrap_or_else(|| {PathBuf::from(".")});
    path.push("airoi");
    std::fs::create_dir_all(&path).unwrap();
    path
}