use capstone::prelude::*;
use std::collections::BTreeMap;

use capstone::Capstone;
use capstone;

use failure::Error;

use image::arch::{Arch, Bits, Endian};
use image::function::Function;
use image::segment::Segments;

#[derive(Debug, Fail)]
pub enum ImageError {
    #[fail(display = "architecture not supported")]
    UnsupportedArchitecture,
}

#[derive(Debug)]
pub struct Image {
    pub arch: Arch,
    pub bits: Bits,
    pub endian: Endian,
    pub segments: Segments,
    pub functions: BTreeMap<u64, Function>,
}

impl Image {
    pub fn is_64bit(&self) -> bool {
        self.bits == Bits::Bits64
    }

    pub fn is_be(&self) -> bool {
        self.endian == Endian::Big
    }

    pub fn disassembler(&self) -> Result<Capstone, Error> {
        match self.arch {
            Arch::Arm if self.is_64bit() => {
                Capstone::new()
                         .arm64()
                         .endian(if self.is_be() { capstone::Endian::Big } else { capstone::Endian::Little })
                         .detail(true)
                         .build()
            },
            Arch::Arm => { 
                Capstone::new()
                         .arm()
                         .mode(capstone::arch::arm::ArchMode::Arm)
                         .endian(if self.is_be() { capstone::Endian::Big } else { capstone::Endian::Little })
                         .detail(true)
                         .build()
            },
            Arch::Mips => {
                Capstone::new()
                         .mips()
                         .mode(if self.is_64bit() { capstone::arch::mips::ArchMode::Mode32 } else { capstone::arch::mips::ArchMode::Mode64 })
                         .endian(if self.is_be() { capstone::Endian::Big } else { capstone::Endian::Little })
                         .detail(true)
                         .build()
            },
            Arch::NotSupported => {
                return Err(ImageError::UnsupportedArchitecture.into())
            },
        }.map_err(Error::from)
    }
}
