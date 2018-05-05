use noisy_float::prelude::*;

use std::collections::BTreeMap;

use image::function::Function;

use analysis::BlockAnalysis;

pub fn compute_scoring(f: &Function, comparisons: &BTreeMap<u64, BlockAnalysis>) -> BTreeMap<u64, R64> {
    let mut dominators = f.compute_dominators();
    let mut uniquely_reachable = BTreeMap::new();

    for sa in f.blocks.keys() {
        if let Some(v) = comparisons.get(sa) {
            // We cannot just unwrap, since some blocks might not be reachable from the start node.
            if let Some(doms) = dominators.remove(&v.destination) {
                if doms.parent == None || doms.parent.unwrap() == *sa {
                    uniquely_reachable.insert(*sa, doms);
                }
            }
        }
    }

    let base_scores = f.blocks.iter().map(|(k, b)| (k, b.base_score())).collect::<BTreeMap<_, _>>();

    base_scores.iter().map(|(k, score)| {
        if let Some(doms) = uniquely_reachable.get(k) {
            let unique_count: usize = doms.dominates.len();
            if unique_count > 0 {
                let coverage: R64 = doms.dominates.iter().map(|k| *base_scores.get(k).unwrap()).sum();
                let dest = comparisons.get(k).unwrap().destination;
                let reachable_count = f.compute_reachable(dest).len();
                let scale = r64(unique_count as f64) / r64(reachable_count as f64);
                (**k, *score + scale * coverage)
            } else {
                (**k, *score)
            }
        } else {
            (**k, r64(0.0))
        }
    }).collect()
}
