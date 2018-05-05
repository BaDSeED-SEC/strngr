use failure::Error;
use itertools::Itertools;
use noisy_float::prelude::*;

use std::ascii;
use std::collections::BTreeMap;
use std::cmp::{Ord, Ordering};

use image::Image;
use image::arch::Endian;
use image::block::Block;
use image::segment::Segments;

use loader::{IDALoader, Loader};
use util::FixedHeap;

pub use self::comparisons::*;
pub use self::metric::*;

mod comparisons;
mod metric;

#[derive(Debug, Eq, PartialEq)]
struct FunctionScores<'a> {
    name: &'a str,
    max_score: R64,
    scores: BTreeMap<u64, R64>,
}

impl<'a> Ord for FunctionScores<'a> {
    fn cmp(&self, other: &FunctionScores) -> Ordering {
        self.max_score.cmp(&other.max_score)
    }
}

impl<'a> PartialOrd for FunctionScores<'a> {
    fn partial_cmp(&self, other: &FunctionScores) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct ZCondBranchAnalysis {
    pub function: u64,
    pub arguments: Accesses<i64>,
    pub destination: u64,
}

pub trait AnalysableBlock {
    fn get_zcond_arguments(&self, n: usize, endian: Endian, mem: &Segments) -> Result<Option<ZCondBranchAnalysis>, Error>;
    fn base_score(&self) -> R64;
}

fn analyse_block(img: &Image, block: &Block) -> Result<Option<ZCondBranchAnalysis>, Error> {
    Ok(block.get_zcond_arguments(3, img.endian, &img.segments)?.map(|info| {
        ZCondBranchAnalysis {
            arguments: Accesses(info.arguments.0.into_iter().map(|access| {
                match access {
                    Access::Constant(v) => {
                        if let Ok(Some(mem)) = img.segments.get_cstring(v as u64, None) {
                            Access::String(v as u64, mem.len())
                        } else {
                            Access::Constant(v)
                        }
                    },
                    v => v,
                }
            }).collect()),
            ..info
        }}))
}

pub fn run(ida_path: &str, input_file: &str, count: usize) -> Result<(), Error> {
    let img = IDALoader::new(ida_path)?.load(input_file)?;
    let cmps = get_static_data_comparisons(&img)?;

    let mut top_functions = FixedHeap::new(count);

    for f in img.functions.values() {
        let scores = compute_scoring(f, &cmps.block_analyses);
        let max_score: R64 = scores.iter().map(|(_, score)| *score).sum(); 

        top_functions.insert(FunctionScores {
            name: &f.name,
            max_score,
            scores
        });
    }

    for score in top_functions.into_inner().into_iter().sorted() {
        println!("[f] {} {:.2}:", score.name, score.max_score);
        for (block, score) in score.scores.iter().sorted_by_key(|&(_, score)| score) {
            if let Some(block_info) = cmps.block_analyses.get(&block) {
                let fun = &img.functions.get(&block_info.function).unwrap().name;

                for arg in block_info.string_arguments.iter().map(|v| {
                    let mut s = String::new();
                    for c in v.iter() {
                        s.extend(ascii::escape_default(*c).map(|c| c as char));
                    }
                    s
                }) {
                    println!("\t{:16} : {:6.2} : via {}", arg, score, fun);
                }
            }
        }
        println!()
    }

    Ok(())
}
