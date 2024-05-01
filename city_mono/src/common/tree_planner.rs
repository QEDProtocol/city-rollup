use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TreePosition {
    pub level: u64,
    pub index: u64,
}
impl TreePosition {
    pub fn new(level: u64, index: u64) -> Self {
        Self { level, index }
    }
    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }
    pub fn get_left_child(&self) -> TreePosition {
        TreePosition::new(self.level - 1, self.index * 2)
    }
    pub fn get_right_child(&self) -> TreePosition {
        TreePosition::new(self.level - 1, self.index * 2 + 1)
    }
    pub fn get_parent(&self) -> TreePosition {
        TreePosition::new(self.level + 1, self.index >> 1)
    }
    pub fn get_span(&self) -> u64 {
        1 << self.level
    }
    pub fn is_null(&self) -> bool {
        self.level == 0xffffu64
    }
    pub fn new_null() -> Self {
        Self {
            level: 0xffffu64,
            index: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BinaryTreeJob {
    pub position: TreePosition,
    pub left_job: TreePosition,
    pub right_job: TreePosition,
}
pub fn gen_leaves_binary_tree_planner(n: usize) -> Vec<BinaryTreeJob> {
    let mut output = Vec::with_capacity(n);
    for i in 0..n {
        output.push(BinaryTreeJob {
            position: TreePosition::new(0, i as u64),
            left_job: TreePosition::new_null(),
            right_job: TreePosition::new_null(),
        });
    }
    output
}
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BinaryTreePlanner {
    pub levels: Vec<Vec<BinaryTreeJob>>,
    pub num_leaves: usize,
}
impl BinaryTreePlanner {
    pub fn new(num_leaves: usize) -> Self {
        let mut current = gen_leaves_binary_tree_planner(num_leaves);
        let mut level_index = 1u64;
        let mut levels: Vec<Vec<BinaryTreeJob>> = Vec::new();
        while current.len() > 1 {
            let mut next_level: Vec<BinaryTreeJob> = Vec::new();
            for i in 0..(current.len() / 2) {
                next_level.push(BinaryTreeJob {
                    position: TreePosition::new(level_index, i as u64),
                    left_job: current[i * 2].position,
                    right_job: current[i * 2 + 1].position,
                });
            }
            let mut n_current = next_level.clone();
            levels.push(next_level);

            if current.len() % 2 == 1 {
                n_current.push(current[current.len() - 1]);
            }
            current = n_current;
            level_index += 1;
        }

        Self { levels, num_leaves }
    }
    pub fn get_graphviz(&self) -> String {
        let mut output = String::new();
        output.push_str("digraph G {\n");
        for level in self.levels.iter() {
            for job in level.iter() {
                output.push_str(&format!(
                    "\"{}:{}\" -> \"{}:{}\";\n",
                    job.position.level, job.position.index, job.left_job.level, job.left_job.index
                ));
                output.push_str(&format!(
                    "\"{}:{}\" -> \"{}:{}\";\n",
                    job.position.level,
                    job.position.index,
                    job.right_job.level,
                    job.right_job.index
                ));
            }
        }
        output.push_str("}\n");
        output
    }
}

#[cfg(test)]
mod tests {
    use super::BinaryTreePlanner;

    #[test]
    fn btree_planner_graphviz() {
        let btp = BinaryTreePlanner::new(6);
        println!("{}", btp.get_graphviz());
    }
    #[test]
    fn btree_planner_json() {
        let btp = BinaryTreePlanner::new(6);

        println!("{}", serde_json::to_string(&btp).unwrap());
    }
}
