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
macro_rules! define_table {
    ($name:ident, $key:ty, $value:ty) => {
        pub const $name: TableDefinition<$key, $value> = TableDefinition::new(stringify!($name));
    };
}

#[macro_export]
macro_rules! define_multimap_table {
    ($name:ident, $key:ty, $value:ty) => {
        pub const $name: MultimapTableDefinition<$key, $value> =
            MultimapTableDefinition::new(stringify!($name));
    };
}

#[macro_export]
macro_rules! async_infinite_loop {
    ($interval:expr, $($body:tt)*) => {
        loop {
            if let Err(err) = (|| async {
                $($body)*

                Ok::<_, anyhow::Error>(())
            })().await {
                println!("Error: {:?}", err);
            }

            tokio::time::sleep(Duration::from_millis($interval)).await;
        }
    };
}

#[macro_export]
macro_rules! sync_infinite_loop {
    ($interval:expr, $($body:tt)*) => {
        loop {
            if let Err(err) = (|| {
                $($body)*

                Ok::<_, anyhow::Error>(())
            })() {
                println!("Error: {:?}", err);
            }

            std::thread::sleep(Duration::from_millis($interval));
        }
    };
}

#[macro_export]
macro_rules! spawn_async_infinite_loop {
    ($interval:expr, $($body:tt)*) => {
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
                    tokio::time::sleep(Duration::from_millis($interval)).await;
                }
            });
        })
    };
}

#[macro_export]
macro_rules! spawn_sync_infinite_loop {
    ($interval:expr, $($body:tt)*) => {
        std::thread::spawn(move || {
            loop {
                if let Err(err) = (|| {
                    $($body)*

                    Ok::<_, anyhow::Error>(())
                })() {
                    println!("Error: {:?}", err);
                }
                std::thread::sleep(Duration::from_millis($interval));
            }
        })
    };
}
/*
concat from https://github.com/inspier/array-concat/blob/bc9e8d0f9a2fcf177286369d976ec38a0a874cc2/src/lib.rs
MIT License

Copyright (c) 2021 inspier

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
/// Computes total size of all provided const arrays.
#[macro_export]
macro_rules! const_concat_arrays_size {
    ($( $array:expr ),*) => {{
        0 $(+ $array.len())*
    }};
}

/// Concatenates provided arrays.
#[macro_export]
macro_rules! const_concat_arrays {
    ($( $array:expr ),*) => ({
        const __ARRAY_SIZE__: usize = $crate::const_concat_arrays_size!($($array),*);

        #[repr(C)]
        struct ArrayConcatDecomposed<T>($([T; $array.len()]),*);

        #[repr(C)]
        union ArrayConcatComposed<T, const N: usize> {
            full: core::mem::ManuallyDrop<[T; N]>,
            decomposed: core::mem::ManuallyDrop<ArrayConcatDecomposed<T>>,
        }

        impl<T, const N: usize> ArrayConcatComposed<T, N> {
            const fn have_same_size(&self) -> bool {
                core::mem::size_of::<[T; N]>() == core::mem::size_of::<Self>()
            }
        }

        let composed = ArrayConcatComposed { decomposed: core::mem::ManuallyDrop::new(ArrayConcatDecomposed ( $($array),* ))};

        // Sanity check that composed's two fields are the same size
        ["Size mismatch"][!composed.have_same_size() as usize];

        // SAFETY: Sizes of both fields in composed are the same so this assignment should be sound
        core::mem::ManuallyDrop::into_inner(unsafe { composed.full })
    });
}

#[macro_export]
macro_rules! capture {
    ($x:ident, $($body:tt)*) => {
        {
            let mut $x = $x.clone();
            $($body)*
        }
    };
    ($x:ident => $y:ident, $($body:tt)*) => {
        {
            let mut $y = $x.clone();
            $($body)*
        }
    };
    ($x:ident . $field_x:ident, $($body:tt)*) => {
        {
            let mut $field_x = $x.$field_x.clone();
            $($body)*
        }
    };
}

#[macro_export]
macro_rules! city_external_rpc_call {
    ($instance:ident, $method:expr, $params:expr, $rtype:ty) => {{
        let response = $instance
            .client
            .post($instance.url)
            .json(&RpcRequest {
                jsonrpc: Version::V2,
                request: ExternalRequestParams {
                    method: $method.to_string(),
                    params: RpcParams($params),
                },
                id: Id::Number(1),
            })
            .send()
            .await?
            .json::<RpcResponse<$rtype>>()
            .await?;

        if let ResponseResult::Success(s) = response.result {
            Ok(s)
        } else {
            Err(anyhow::format_err!("rpc call failed"))
        }
    }};
}

#[macro_export]
macro_rules! city_rpc_call {
    ($instance:ident, $params:expr) => {{
        let response = $instance
            .client
            .post($instance.url)
            .json(&RpcRequest {
                jsonrpc: Version::V2,
                request: $params,
                id: Id::Number(1),
            })
            .send()
            .await?
            .json::<RpcResponse<()>>()
            .await?;

        if let ResponseResult::Success(s) = response.result {
            Ok(s)
        } else {
            Err(anyhow::format_err!("rpc call failed"))
        }
    }};
}
