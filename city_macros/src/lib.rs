#[macro_export]
macro_rules! set_state {
    ($instance:expr,$checkpoint_id:expr,$pos:expr,$value:expr) => {
        Sha256StateRootTree::<S>::set_leaf(
            &mut $instance,
            &KVQMerkleNodeKey::from_identifier_position_ref(
                &SHA256_STATE_ROOT_TREE_ID,
                $checkpoint_id,
                &$pos,
            ),
            $value,
        )?;
        Blake3StateRootTree::<S>::set_leaf(
            &mut $instance,
            &KVQMerkleNodeKey::from_identifier_position_ref(
                &BLAKE3_STATE_ROOT_TREE_ID,
                $checkpoint_id,
                &$pos,
            ),
            $value,
        )?;
        Keccak256StateRootTree::<S>::set_leaf(
            &mut $instance,
            &KVQMerkleNodeKey::from_identifier_position_ref(
                &KECCAK256_STATE_ROOT_TREE_ID,
                $checkpoint_id,
                &$pos,
            ),
            $value,
        )?;
        PoseidonGoldilocksStateRootTree::<S>::set_leaf(
            &mut $instance,
            &KVQMerkleNodeKey::from_identifier_position_ref(
                &POSEIDONGOLDILOCKS_STATE_ROOT_TREE_ID,
                $checkpoint_id,
                &$pos,
            ),
            hash256_to_goldilocks_hash(&$value),
        )?;
    };
}

#[macro_export]
macro_rules! get_state {
    ($hash:expr,$instance:expr,$checkpoint_id:expr,$pos:expr,$get_fn:tt,$convert_fn:path) => {
        match $hash {
            CityAHashFunction::Sha256 => Sha256StateRootTree::<S>::$get_fn(
                $instance,
                &KVQMerkleNodeKey::from_identifier_position_ref(
                    &SHA256_STATE_ROOT_TREE_ID,
                    $checkpoint_id,
                    &$pos,
                ),
            ),
            CityAHashFunction::BLAKE3 => Blake3StateRootTree::<S>::$get_fn(
                $instance,
                &KVQMerkleNodeKey::from_identifier_position_ref(
                    &BLAKE3_STATE_ROOT_TREE_ID,
                    $checkpoint_id,
                    &$pos,
                ),
            ),
            CityAHashFunction::Keccak256 => Keccak256StateRootTree::<S>::$get_fn(
                $instance,
                &KVQMerkleNodeKey::from_identifier_position_ref(
                    &KECCAK256_STATE_ROOT_TREE_ID,
                    $checkpoint_id,
                    &$pos,
                ),
            ),
            CityAHashFunction::PoseidonGoldilocks => {
                let p = PoseidonGoldilocksStateRootTree::<S>::$get_fn(
                    $instance,
                    &KVQMerkleNodeKey::from_identifier_position_ref(
                        &POSEIDONGOLDILOCKS_STATE_ROOT_TREE_ID,
                        $checkpoint_id,
                        &$pos,
                    ),
                )?;
                Ok($convert_fn(&p))
            }
        }
    };
}

#[macro_export]
macro_rules! rpc_call {
    ($instance:ident,$param:expr, $rtype:ty) => {{
        let response = $instance
            .client
            .post(&$instance.url)
            .json(&RpcRequest {
                jsonrpc: Version::V2,
                request: $param,
                id: Id::Number(1),
            })
            .send()
            .await?
            .json::<Value>()
            .await?;

        Ok(serde_json::from_value::<$rtype>(
            response["result"].clone(),
        )?)
    }};
}

// https://www.reddit.com/r/rust/comments/17ln23t/change_my_mind_rust_should_use_the_operator_to/
// ¿
#[macro_export]
macro_rules! quick {
    ($fn_result:expr) => {{
        match $fn_result {
            Ok(res) => return Ok(res),
            Err(err) => err,
        }
    }};
}

#[macro_export]
macro_rules! impl_kvq_serialize {
    ($($typ:ty),+ $(,)?) => {
        $(
            impl KVQSerializable for $typ {
                fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
                    Ok(self.to_le_bytes().to_vec())
                }
                fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
                    Ok(<$typ>::from_le_bytes(bytes.try_into()?))
                }
            }
        )+
    };
}

#[macro_export]
macro_rules! async_infinite_loop {
    ($($body:tt)*) => {
        loop {
            if let Err(err) = (|| async {
                $($body)*

                Ok::<_, anyhow::Error>(())
            })().await {
                println!("Error: {:?}", err);
            }
        }
    };
}

#[macro_export]
macro_rules! spawn_async_infinite_loop {
    ($($body:tt)*) => {
        std::thread::spawn(move || {
          let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

            rt.block_on(async move {
                loop {
                    if let Err(err) = (|| async {
                        $($body)*

                        Ok::<_, anyhow::Error>(())
                    })().await {
                        println!("Error: {:?}", err);
                    }
                }
            });
        })
    };
}
