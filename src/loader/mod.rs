use std::path::Path;

use failure::Error;

use image::Image;

pub mod ida;

pub use self::ida::Loader as IDALoader;

pub trait Loader {
    fn load<P: AsRef<Path>>(&self, p: P) -> Result<Image, Error>;
}
