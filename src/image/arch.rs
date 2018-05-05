#[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
pub enum Arch {
    Arm,
    Mips,
    NotSupported,
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
pub enum Bits {
    Bits32,
    Bits64,
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
pub enum Endian {
    Big,
    Little,
}
