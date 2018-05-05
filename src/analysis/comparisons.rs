use failure::Error;
use noisy_float::prelude::*;
use num_traits::*;

use std::collections::BTreeMap;

use image::Image;

use analysis::analyse_block;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Access<T> {
    Stack,
    Register,
    Constant(T),
    String(u64, usize),
    Other,
    Never,
}

#[derive(Debug)]
pub struct Accesses<T>(pub Vec<Access<T>>);

#[derive(Debug)]
pub struct BlockAnalysis<'a> {
    pub function: u64,
    pub destination: u64,
    pub string_arguments: Vec<&'a [u8]>,
}

#[derive(Debug)]
pub struct ComparisonAnalyses<'a> {
    pub function_scores: BTreeMap<u64, R64>,
    pub block_analyses: BTreeMap<u64, BlockAnalysis<'a>>,
}

pub trait Constant : PrimInt + WrappingAdd {
    fn normalise(&self) -> i64 {
        // FIXME: This won't work for certain 64-bit arch. addresses
        <Self as ToPrimitive>::to_i64(self).unwrap()
    }

    fn as_address(&self) -> u64 {
        <Self as ToPrimitive>::to_i64(self).unwrap() as u64
    }
}

impl Constant for i32 { }
impl Constant for i64 { }
impl Constant for u64 { }

impl<T: Constant> Access<T> {
    pub fn map_constant<F, U>(&self, f: F) -> Access<U>
        where F: Fn(T) -> U {
        match *self {
            Access::Constant(v) => Access::Constant(f(v)),
            Access::String(sa, len) => Access::String(sa, len),
            Access::Stack => Access::Register,
            Access::Register => Access::Register,
            Access::Other => Access::Other,
            Access::Never => Access::Never,
        }
    }

    pub fn wrapping_add(&self, v: T) -> Access<T> {
        match *self {
            Access::Constant(u) => Access::Constant(u.wrapping_add(&v)),
            x => x,
        }
    }
}

impl<T: Constant> Accesses<T> {
    pub fn new(n: usize) -> Accesses<T> {
        Accesses(vec![Access::Never; n])
    }

    #[allow(unused)]
    pub fn get(&self, n: usize) -> &Access<T> {
        &self.0[n]
    }

    pub fn get_mut(&mut self, n: usize) -> &mut Access<T> {
        &mut self.0[n]
    }
}

pub fn get_static_data_comparisons(img: &Image) -> Result<ComparisonAnalyses, Error> {
    let mut scores = BTreeMap::new();
    let mut cstring_blocks = BTreeMap::new();

    for f in img.functions.values() {
        let mut fscores = BTreeMap::new();
        for b in f.blocks.values() {
            if let Some(info) = analyse_block(&img, &**b)? {
                let mut strs = Vec::new();
                let mut nregs = 0;
                let mut nstack = 0;
                let mut _nconst = 0;
                let mut _nother = 0;

                for arg in info.arguments.0.iter().take_while(|arg| **arg != Access::Never) {
                    match arg {
                        &Access::Stack => nstack += 1,
                        &Access::Register => nregs += 1,
                        &Access::Constant(_) => _nconst +=1,
                        &Access::String(addr, len) => {
                            let st = img.segments.get_cstring(addr, Some(len+1)).unwrap().unwrap();
                            strs.push(st);
                        },
                        &Access::Other => _nother += 1,
                        &Access::Never => unreachable!(),
                    }
                }

                if strs.len() > 0 && (nregs >= 1 || nstack >= 1) && strs.iter().all(|v| !v.contains(&b'%') || !v.contains(&b'\t')) {
                    let mut v = fscores.entry(info.function).or_insert(r64(0.0));
                    *v += r64(1.0);

                    cstring_blocks.insert(b.start_addr(), BlockAnalysis {
                        function: info.function,
                        string_arguments: strs,
                        destination: info.destination,
                    });
                }
            }
        }

        if fscores.len() == 1 {
            fscores.iter_mut().map(|(_, v)| *v *= r64(1.2)).next();
        }

        for (k, v) in fscores.into_iter() {
            *scores.entry(k).or_insert(r64(0.0)) += v;
        }
    }
    Ok(ComparisonAnalyses { function_scores: scores, block_analyses: cstring_blocks })
}

