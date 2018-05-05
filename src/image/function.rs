use std::collections::{BTreeMap, BTreeSet};

use image::block::Block;

#[derive(Debug)]
pub struct Function {
    pub name: String,
    pub start_addr: u64,
    pub end_addr: u64,
    pub blocks: BTreeMap<u64, Box<Block>>,
}

#[derive(Debug)]
pub struct Dominates {
    pub parent: Option<u64>,
    pub dominates: Vec<u64>,
}

impl Function {
    // Implements "A Simple, Fast Dominance Algorithm" by Cooper et al., see:
    // https://www.cs.rice.edu/~keith/EMBED/dom.pdf
    pub fn compute_immediate_dominators(&self) -> BTreeMap<u64, u64> {
        let mut idoms = BTreeMap::new();

        // Compute predecessors and ordering traversal using DFS
        let mut preds = BTreeMap::new();
        let mut seen = BTreeSet::new();
        let mut ordering = Vec::with_capacity(self.blocks.len());
        let mut work_stack = vec![self.start_addr];

        while let Some(v) = work_stack.pop() {
            if !seen.contains(&v) {
                ordering.push(v);
                seen.insert(v);
                for d in self.blocks.get(&v).unwrap().dests() {
                    work_stack.push(*d);
                    preds.entry(d).or_insert_with(Vec::new).push(v);
                }
            }
        }

        let ordering_idxs = ordering.iter()
                                    .enumerate()
                                    .map(|(k, v)| (*v, k))
                                    .collect::<BTreeMap<u64, usize>>();


        let mut changed = true;
        idoms.insert(self.start_addr, self.start_addr);

        while changed {
            changed = false;
            for b in &ordering[1..] {
                if let Some(b_preds) = preds.get(b) {
                    let mut new_idom = *b_preds.iter()
                                               .find(|p| idoms.get(*p).is_some())
                                               .unwrap();
                    for p in b_preds.iter().filter(move |p| **p != new_idom) {
                        if idoms.get(p).is_some() {
                            new_idom = intersect(&idoms, &ordering, &ordering_idxs, *p, new_idom);
                        }
                    }
                    let idoms_b = idoms.entry(*b).or_insert(0);
                    if *idoms_b != new_idom {
                        *idoms_b = new_idom;
                        changed = true;
                    }
                }
            }
        }

        idoms
    }

    // FIXME: Inefficient
    pub fn compute_dominators(&self) -> BTreeMap<u64, Dominates> {
        let idoms = self.compute_immediate_dominators();
        let mut dominators = BTreeMap::new();

        for (c, p) in idoms.iter() {
            let mut p_dom = *p;

            loop {
                let np_dom = *idoms.get(&p_dom).unwrap(); 
                let ent = dominators.entry(p_dom)
                                    .or_insert_with(|| {
                                        Dominates {
                                            parent: if p_dom != self.start_addr { Some(np_dom) } else { None },
                                            dominates: Vec::new(),
                                        }
                                    });
                ent.dominates.push(*c);
                if p_dom == np_dom { break } else { p_dom = np_dom };
            }

            dominators.entry(*c)
                      .or_insert_with(|| Dominates {
                          parent: if p_dom != self.start_addr { Some(*idoms.get(&p_dom).unwrap()) } else { None },
                          dominates: Vec::new(),
                      });
        }
        dominators
    }

    pub fn compute_reachable(&self, start_addr: u64) -> BTreeSet<u64> {
        let mut reachable = BTreeSet::new();
        let mut work_stack = vec![start_addr];

        while let Some(v) = work_stack.pop() {
            if !reachable.contains(&v) {
                reachable.insert(v);
                for d in self.blocks.get(&v).unwrap().dests() {
                    work_stack.push(*d);
                }
            }
        }

        reachable
    }
}

// TODO: Perform computations on indexes not addrs
fn intersect(idoms: &BTreeMap<u64, u64>,
             ordering: &[u64],
             ordering_idxs: &BTreeMap<u64, usize>,
             b1: u64,
             b2: u64) -> u64 {
    let mut finger1 = *ordering_idxs.get(&b1).unwrap();
    let mut finger2 = *ordering_idxs.get(&b2).unwrap();

    // NOTE: This differs from the original algorithm because we assign IDs in reverse order
    while finger1 != finger2 {
        while finger1 > finger2 {
            finger1 = *ordering_idxs.get(idoms.get(&ordering[finger1]).unwrap()).unwrap();
        }
        while finger2 > finger1 {
            finger2 = *ordering_idxs.get(idoms.get(&ordering[finger2]).unwrap()).unwrap();
        }
    }

    ordering[finger1]
}
