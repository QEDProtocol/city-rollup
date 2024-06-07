pub fn get_user_id_from_leaf_id(leaf_id: u64) -> anyhow::Result<u64> {
    tracing::info!("got leaf_id {}", leaf_id);
    if leaf_id & 1u64 != 0 {
        anyhow::bail!("Leaf id is not even")
    } else {
        Ok(leaf_id >> 1u64)
    }
}
pub fn get_user_ids(leaf_ids: &[u64]) -> anyhow::Result<Vec<u64>> {
    let results: Vec<u64> = leaf_ids
        .iter()
        .map(|x| get_user_id_from_leaf_id(*x))
        .collect::<anyhow::Result<Vec<u64>>>()?;
    Ok(results)
}
fn main() {
    let inputs: Vec<u64> = vec![2, 4, 1, 8, 10, 20, 30, 40, 50];

    let results = get_user_ids(&inputs);
    if results.is_err() {
        tracing::info!("Error: {:?}", results.err().unwrap());
    } else {
        let results = results.unwrap();
        tracing::info!("Results: {:?}", results);
    }
    /*
    let mut ctr = 0;
    let results: anyhow::Result<Vec<u64>> = inputs
        .iter()
        .map(|x| {
            ctr = ctr + 1;
            get_user_id_from_leaf_id(*x)
        })
        .collect();
    tracing::info!("ctr: {}", ctr);
    if results.is_err() {
        tracing::info!("Error: {:?}", results.err().unwrap());
    } else {
        let results = results.unwrap();
        tracing::info!("Results: {:?}", results);
    }*/
}
