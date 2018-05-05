use byteorder::{BE, LE};
use capstone::prelude::*;
use capstone::{Capstone, Insn, Mode};
use capstone::arch::ArchOperand;
use capstone::arch::arm::{ArmCC, ArmInsn, ArmOperand, ArmOperandType, ArmReg};
use failure::Error;
use itertools::Itertools;
use itertools::FoldWhile::{Continue, Done};
use noisy_float::prelude::*;

use std::collections::{BTreeMap, BTreeSet};
use std::mem;

use analysis::{Access, Accesses, AnalysableBlock, Constant, ZCondBranchAnalysis};
use image::arch::Endian;
use image::block;
use image::segment::Segments;

#[derive(Debug)]
pub struct Instruction {
    insn: Insn,
    cc: ArmCC,
    operands: Vec<ArmOperand>,
    reg_reads: Vec<RegId>,
    reg_writes: Vec<RegId>,
}

#[derive(Debug)]
pub struct Block {
    start_addr: u64,
    end_addr: u64,
    is_thumb: bool,
    dests: Vec<u64>,
    insns: Vec<Instruction>,
}

fn reg_to_arg_id(reg: RegIdInt) -> Option<usize> {
    let id = match reg as u32 {
        ArmReg::ARM_REG_R0 => 0,
        ArmReg::ARM_REG_R1 => 1,
        ArmReg::ARM_REG_R2 => 2,
        ArmReg::ARM_REG_R3 => 3,
        ArmReg::ARM_REG_R4 => 4,
        _ => return None,
    };
    Some(id)
}

impl Instruction {
    pub fn id(&self) -> ArmInsn {
        unsafe { mem::transmute::<u32, ArmInsn>(self.insn.id().0) }
    }

    pub fn is_call(&self) -> bool {
        self.id() == ArmInsn::ARM_INS_BL || self.id() == ArmInsn::ARM_INS_BLX
    }
}

impl Block {
    pub fn new(start_addr: u64,
               end_addr: u64,
               dests: Vec<u64>,
               is_thumb: bool,
               data: &[u8],
               cs: &mut Capstone) -> Result<Block, Error> {
        cs.set_mode(if is_thumb { Mode::Thumb } else { Mode::Arm })?;
        let insn = cs.disasm_all(data, start_addr)?
                     .iter()
                     .map(|insn| {
                         let (cc, operands) = {
                             let id = cs.insn_detail(&insn)?;
                             let dtl = id.arch_detail();
                             let cc = dtl.arm().unwrap().cc();
                             let ops = dtl.operands()
                                 .into_iter()
                                 .map(|op| {
                                     if let ArchOperand::ArmOperand(aop) = op {
                                         aop
                                     } else {
                                         // Should never reach here.
                                         unreachable!()
                                     }
                                 })
                                 .collect::<Vec<ArmOperand>>();
                            (cc, ops)
                         };
                         let (reg_reads, reg_writes) = cs.access(&insn)?;
                         Ok(Instruction {
                             insn,
                             operands,
                             cc,
                             reg_reads: reg_reads.iter().map(|x| RegId(*x as RegIdInt)).collect(),
                             reg_writes: reg_writes.iter().map(|x| RegId(*x as RegIdInt)).collect(),
                         })
                     })
                     .collect::<Result<Vec<_>, Error>>()?;

        Ok(Block {
            start_addr,
            end_addr,
            is_thumb,
            insns: insn,
            dests,
        })
    }
}

impl block::Block for Block {
    fn start_addr(&self) -> u64 {
        self.start_addr
    }

    fn end_addr(&self) -> u64 {
        self.end_addr
    }

    fn dests(&self) -> &[u64] {
        &self.dests
    }

    fn into_boxed(self) -> Box<block::Block> {
        Box::new(self)
    }
}

impl AnalysableBlock for Block {
    fn get_zcond_arguments(&self, n: usize, endian: Endian, mem: &Segments) -> Result<Option<ZCondBranchAnalysis>, Error> {
        let mut insns = self.insns.iter().rev();
        // FIXME: Ugly. Performs check on each use; can we get address of monomorphised function?
        let get_i32 = |v| if endian == Endian::Big { mem.get_i32::<BE>(v) } else { mem.get_i32::<LE>(v) };

        let cond = if let Some(insn) = insns.next() {
            insn
        } else {
            return Ok(None)
        };

        // Pattern 1: CB(Z|NZ) RX, ...
        let (reg_id, dest) = if (cond.id() == ArmInsn::ARM_INS_CBZ || cond.id() == ArmInsn::ARM_INS_CBNZ)
            && cond.cc == ArmCC::ARM_CC_AL {
                if let ArmOperandType::Reg(id) = cond.operands[0].op_type {
                    match cond.id() {
                        ArmInsn::ARM_INS_CBZ => {
                            if let ArmOperandType::Imm(dest) = cond.operands[1].op_type {
                                (id, dest as u64)
                            } else {
                                return Ok(None)
                            }
                        },
                        ArmInsn::ARM_INS_CBNZ => {
                            let dest = if let ArmOperandType::Imm(other_dest) = cond.operands[1].op_type {
                                let addr = other_dest as u64;
                                self.dests.iter().find(|v| **v != addr)
                            } else {
                                self.dests.iter().next()
                            };
                            if dest.is_some() { (id, *dest.unwrap()) } else { return Ok(None) }
                        },
                        _ => unreachable!(),
                    }
                } else {
                    return Ok(None)
                }
        // Pattern 2: CMP        RX, 0
        //            BX?(EQ|NE) ...
        } else if (cond.id() == ArmInsn::ARM_INS_B || cond.id() == ArmInsn::ARM_INS_BX)
            && (cond.cc == ArmCC::ARM_CC_EQ || cond.cc == ArmCC::ARM_CC_NE) {
            let comp = if let Some(cond) = insns.next() {
                cond
            } else {
                return Ok(None)
            };

            let dest = match cond.cc {
                ArmCC::ARM_CC_EQ => {
                    if let ArmOperandType::Imm(dest) = cond.operands[0].op_type {
                        dest as u64
                    } else {
                        return Ok(None)
                    }
                },
                ArmCC::ARM_CC_NE => {
                    let dest = if let ArmOperandType::Imm(other_dest) = cond.operands[0].op_type {
                        let addr = other_dest as u64;
                        self.dests.iter().find(|v| **v != addr)
                    } else {
                        self.dests.iter().next()
                    };
                    if dest.is_some() { *dest.unwrap() } else { return Ok(None) }
                },
                _ => unreachable!(),
            };

            if comp.id() == ArmInsn::ARM_INS_CMP && comp.cc == ArmCC::ARM_CC_AL {
                match (&comp.operands[0].op_type, &comp.operands[1].op_type) {
                    (&ArmOperandType::Reg(id), &ArmOperandType::Imm(0)) |
                    (&ArmOperandType::Imm(0), &ArmOperandType::Reg(id)) => (id, dest),
                    _ => return Ok(None)
                }
            } else {
                return Ok(None)
            }
        } else {
            return Ok(None)
        };

        // Find the call and depends
        let mut taint = BTreeSet::new(); taint.insert(reg_id.0);

        let call = insns.fold_while(None, |acc, insn| {
            if insn.is_call() {
                if let ArmOperandType::Imm(addr) = insn.operands[0].op_type {
                    if taint.contains(&(ArmReg::ARM_REG_R0 as u16)) {
                        Done(Some(addr as u64))
                    } else {
                        Done(None)
                    }
                } else {
                    Done(None)
                }
            } else {
                // if tracked registers in insn.reg_writes, then replace tracked with
                // reg_reads
                for rw in insn.reg_writes.iter() {
                    if taint.contains(&rw.0) {
                        taint.remove(&rw.0);
                        taint.extend(insn.reg_reads.iter().map(|x| x.0));
                    }
                }
                Continue(acc)
            }
        })
        .into_inner();

        // Estimate the arguments to the call; we require emulation of three instructions:
        // MOV, LDR, ADD
        if call.is_none() { return Ok(None) };

        let mut vals: BTreeMap<u16, Access<i32>> = BTreeMap::new();

        for insn in insns.take_while(|insn| !insn.is_call()).collect::<Vec<_>>().iter().rev() {
            match insn.id() {
                ArmInsn::ARM_INS_ADD => {
                    if let ArmOperandType::Reg(target) = insn.operands[0].op_type {
                        let reg_id = target.0;
                        match insn.operands[1].op_type {
                            ArmOperandType::Imm(to_add) => {
                                if vals.get_mut(&reg_id).map(|value| *value = value.wrapping_add(to_add)).is_none() {
                                    vals.insert(reg_id, Access::Other);
                                }
                            },
                            ArmOperandType::Reg(source) if source.0 as u32 == ArmReg::ARM_REG_PC => {
                                if vals.get_mut(&reg_id).map(|value| {
                                    // PC is two instructions ahead of current instruction address
                                    let pc_offset = if self.is_thumb { 4 } else { 8 };
                                    let addr = (insn.insn.address() as i32).wrapping_add(pc_offset);
                                    *value = value.wrapping_add(addr);

                                    // On Thumb, "the value of the PC is the address of the current instruction plus 4 bytes, with
                                    // bit[1] of the result cleared to 0 to make it word-aligned."
                                    if self.is_thumb { *value = value.map_constant(|v| v & !2) };
                                }).is_none() {
                                    vals.insert(reg_id, Access::Other);
                                }
                            },
                            ArmOperandType::Reg(source) if source.0 as u32 == ArmReg::ARM_REG_SP => {
                                vals.insert(reg_id, Access::Stack);
                            },
                            _ => { vals.insert(reg_id, Access::Other); },
                        }
                    }
                },
                ArmInsn::ARM_INS_LDR => {
                    if let ArmOperandType::Reg(target) = insn.operands[0].op_type {
                        match insn.operands[1].op_type {
                            ArmOperandType::Reg(source) => {
                                // TODO: actually fetch
                                match vals.get(&source.0).map(|x| *x) {
                                    Some(value) => { vals.insert(target.0, value); },
                                    None => { vals.insert(target.0, Access::Register); },
                                }
                            },
                            ArmOperandType::Imm(imm) => { 
                                // TODO: actually fetch
                                vals.insert(target.0, Access::Constant(get_i32(imm.normalise() as u64)?));
                            },
                            ArmOperandType::Mem(ref m) => {
                                // Skip non-immediate offset
                                if m.index() != 0 {
                                    continue;
                                }

                                // Handle two cases: PC-relative and known register relative
                                if m.base().0 as u32 == ArmReg::ARM_REG_PC {
                                    // PC is two instructions ahead of current instruction address
                                    let pc_offset = if self.is_thumb { 4 } else { 8 };
                                    let mut addr = (insn.insn.address() as i32).wrapping_add(pc_offset).wrapping_add(m.disp());

                                    // On Thumb, "the value of the PC is the address of the current instruction plus 4 bytes, with
                                    // bit[1] of the result cleared to 0 to make it word-aligned."
                                    if self.is_thumb { addr &= !2 };

                                    vals.insert(target.0, Access::Constant(get_i32(addr.normalise() as u64)?));
                                } else if m.base().0 as u32 == ArmReg::ARM_REG_SP {
                                    vals.insert(target.0, Access::Stack);
                                } else {
                                    // TODO: actually fetch
                                    match vals.get(&(m.base().0 as u16)).map(|x| *x) {
                                        Some(value) => { vals.insert(target.0, value.wrapping_add(m.disp())); },
                                        None => { vals.insert(target.0, Access::Register); },
                                    }
                                }
                            },
                            _ => (),
                        }
                    }
                },
                ArmInsn::ARM_INS_MOV => {
                    if let ArmOperandType::Reg(target) = insn.operands[0].op_type {
                        // TODO: Handle "Flexible second operand"
                        match insn.operands[1].op_type {
                            ArmOperandType::Reg(source) if source.0 as u32 == ArmReg::ARM_REG_PC => {
                                let pc_offset = if self.is_thumb { 4 } else { 8 };
                                let mut addr = (insn.insn.address() as i32).wrapping_add(pc_offset);

                                // On Thumb, "the value of the PC is the address of the current instruction plus 4 bytes, with
                                // bit[1] of the result cleared to 0 to make it word-aligned."
                                if self.is_thumb { addr &= !2 };
                                vals.insert(target.0, Access::Constant(addr));
                            },
                            ArmOperandType::Reg(source) if source.0 as u32 == ArmReg::ARM_REG_SP => {
                                vals.insert(target.0, Access::Stack);
                            },
                            ArmOperandType::Reg(source) => {
                                match vals.get(&source.0).map(|x| *x) {
                                    Some(value) => { vals.insert(target.0, value); },
                                    None => { vals.insert(target.0, Access::Register); },
                                }
                            },
                            ArmOperandType::Imm(imm) => { vals.insert(target.0, Access::Constant(imm)); },
                            _ => (),
                        }
                    }
                },
                ArmInsn::ARM_INS_MOVW => {
                    if let ArmOperandType::Reg(target) = insn.operands[0].op_type {
                        if let ArmOperandType::Imm(imm) = insn.operands[1].op_type {
                            vals.insert(target.0, Access::Constant(imm)); 
                        } else {
                            vals.insert(target.0, Access::Other);
                        }
                    }
                },
                ArmInsn::ARM_INS_MOVT => {
                    if let ArmOperandType::Reg(target) = insn.operands[0].op_type {
                        if let ArmOperandType::Imm(imm) = insn.operands[1].op_type {
                            if vals.get_mut(&target.0).map(|value| *value = value.map_constant(|v| v & 0xffff | (imm << 16))).is_none() {
                                vals.insert(target.0, Access::Other);
                            }
                        } else {
                            vals.insert(target.0, Access::Other);
                        }
                    }
                },
                _ => {
                    for rw in insn.reg_writes.iter() {
                        vals.insert(rw.0, Access::Other);
                    }
                },
            }
        };

        let mut accesses = Accesses::new(n);

        for (r, v) in vals.into_iter().filter_map(|(r, v)| reg_to_arg_id(r).and_then(|r| if r < n { Some((r, v)) } else { None })) {
            *accesses.get_mut(r) = v.map_constant(|v| v.normalise());
        }

        Ok(Some(ZCondBranchAnalysis {
            function: call.unwrap(),
            arguments: accesses,
            destination: dest,
        }))
    }

    fn base_score(&self) -> R64 {
        r64(self.insns.len() as f64)
    }
}

