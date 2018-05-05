use std::fs::File;
use std::path::Path;
use std::collections::BTreeMap;

use capstone::Capstone;
use failure::Error;
use rida::{Type, IDA};
use serde_json;
use tempfile;

use image::Image;
use image::arch::{Arch, Bits, Endian};
use image::function::Function;
use image::segment::Segments;

use arch::arm::Block as ArmBlock;
use image::block::Block;

use loader;

macro_rules! PYLOADER { ($e:expr) => (format!(r#"
from idaapi import *
from idautils import *

import base64
import json

# Adapted from keystone; see: https://github.com/keystone-engine/keypatch/blob/bfcaef11de3a90efb08ed4f0c39dccf40d5613d0/keypatch.py
def get_meta():
    binary_info = dict()

    # heuristically detect hardware setup
    info = idaapi.get_inf_structure()
    
    try:
        cpuname = info.procname.lower()
    except:
        cpuname = info.procName.lower()

    try:
        # since IDA7 beta 3 (170724) renamed inf.mf -> is_be()/set_be()
        is_be = idaapi.cvar.inf.is_be()
    except:
        # older IDA versions
        is_be = idaapi.cvar.inf.mf

    binary_info['bits'] = 'Bits64' if info.is_64bit() else 'Bits32'
    binary_info['endian'] = 'Big' if is_be else 'Little'
    
    if cpuname.startswith("arm"):
        binary_info['arch'] = 'Arm'
    elif cpuname.startswith("mips"):
        binary_info['arch'] = 'Mips'
    else:
        binary_info['arch'] = 'NotSupported'

    return binary_info


autoWait()

image = get_meta()
image['segments'] = []
image['functions'] = []

for ea in Segments():
    seg = dict()
    seg['name'] = SegName(ea)
    seg['start_addr'] = SegStart(ea)
    seg['end_addr'] = SegEnd(ea)

    # Handle case of, e.g., .bss in IDA giving None for GetManyBytes
    try:
        seg['bytes'] = base64.b64encode(GetManyBytes(SegStart(ea), SegEnd(ea) - SegStart(ea)))
    except:
        seg['bytes'] = ''

    image['segments'].append(seg)

    for fn_entry_address in Functions(SegStart(ea), SegEnd(ea)):
        fn_name = GetFunctionName(fn_entry_address)
        fn = get_func(fn_entry_address)

        inst = dict()
        inst['name'] = fn_name
        inst['start_addr'] = fn.startEA
        inst['end_addr'] = fn.endEA
        inst['blocks'] = []

        for fn_block in FlowChart(fn):
            block = dict()
            block['start_addr'] = fn_block.startEA
            block['end_addr'] = fn_block.endEA
            block['t_reg'] = GetReg(fn_block.startEA, 'T') == 1
            block['dests'] = []

            for block_succ in fn_block.succs():
                block['dests'].append(block_succ.startEA)

            inst['blocks'].append(block)

        image['functions'].append(inst)


with open('{}', 'w+') as f:
    json.dump(image, f)
Exit(0)
"#, $e)) }

pub struct Loader(IDA);

#[derive(Debug, Deserialize)]
struct ImageRaw {
    arch: Arch,
    bits: Bits,
    endian: Endian,
    segments: Segments,
    functions: Vec<FunctionRaw>,
}

#[derive(Debug, Deserialize)]
struct FunctionRaw {
    name: String,
    start_addr: u64,
    end_addr: u64,
    blocks: Vec<BlockRaw>,
}

#[derive(Debug, Deserialize)]
struct BlockRaw {
    start_addr: u64,
    end_addr: u64,
    t_reg: bool, // For ARM
    dests: Vec<u64>,
}

impl Loader {
    pub fn new(ida_path: &str) -> Result<Loader, Error> {
        Ok(Loader(IDA::new(ida_path)?.script_type(Type::Python)))
    }

    fn lift_function(img: &Image, f: FunctionRaw, dis: &mut Capstone) -> Result<Function, Error> {
        let bvs = f.blocks.into_iter();
        let mut blocks = BTreeMap::new();

        for bv in bvs {
            let data = img.segments.get_bytes(bv.start_addr, bv.end_addr)?;
            let block = match img.arch {
                Arch::Arm => {
                    ArmBlock::new(bv.start_addr, bv.end_addr, bv.dests, bv.t_reg, data, dis)?
                        .into_boxed()
                },
                _ => {
                    unimplemented!()
                },
            };
            blocks.insert(bv.start_addr, block);
        }

        Ok(Function {
            name: f.name,
            start_addr: f.start_addr,
            end_addr: f.end_addr,
            blocks,
        })
    }
}

impl loader::Loader for Loader {
    fn load<P: AsRef<Path>>(&self, p: P) -> Result<Image, Error> {
        let json = tempfile::Builder::new()
            .suffix("json")
            .tempfile()?;

        let json_path = json.into_temp_path();

        self.0.run(&PYLOADER!(json_path.display()), p.as_ref().to_str().unwrap())?;

        let json = File::open(&json_path)?;

        let raw = serde_json::from_reader::<_, ImageRaw>(&json)?;

        let mut image = Image {
            arch: raw.arch,
            bits: raw.bits,
            endian: raw.endian,
            segments: raw.segments,
            functions: BTreeMap::new(),
        };

        let mut cs = image.disassembler()?;

        for f in raw.functions.into_iter() {
            let v = Loader::lift_function(&image, f, &mut cs)?;
            image.functions.insert(v.start_addr, v);
        }

        Ok(image)
    }
}

