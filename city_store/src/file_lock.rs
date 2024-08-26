use std::{
    fs::OpenOptions,
};
use fs2::FileExt;
use strum_macros::{AsRefStr, Display, EnumString};
use crate::config::LOCK_FILE_PATH;

#[allow(dead_code)]
pub struct FileLock {
    file: std::fs::File, //the lock's lifetime is tied to the file.
    pub status: FileLockStatus,
}
#[derive(Debug, Clone, Eq, PartialEq, EnumString, Display, AsRefStr)]
pub enum FileLockStatus {
    #[strum(serialize = "FileAlreadyExistedAndLocked")]
    FileAlreadyExistedAndLocked,
    #[strum(serialize = "FileCreatedAndLocked")]
    FileCreatedAndLocked,
}

pub fn try_lock() -> Result<FileLock, String> {
    match check_and_lock_file(LOCK_FILE_PATH) {
        Some(file_lock) => Ok(file_lock),
        None => Err("Another instance of the program is already running.".to_string())
    }
}
fn check_and_lock_file(path: &str) -> Option<FileLock> {
    let file_exists = std::fs::metadata(path).is_ok();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path);

    match file {
        Ok(f) => {
            if f.try_lock_exclusive().is_ok() {
                let status = if file_exists{
                    // The file already existed and was locked successfully.
                    FileLockStatus::FileAlreadyExistedAndLocked
                }else {
                    // The file was just created and locked.
                    FileLockStatus::FileCreatedAndLocked
                };
                Some(FileLock { file: f, status })
            }else {
                None
            }

        }
        Err(e) => {
            eprintln!("Failed to open or create the lock file: {}", e);
            None
        }
    }
}
