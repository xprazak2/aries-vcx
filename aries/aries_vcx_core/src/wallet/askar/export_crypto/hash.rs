use crate::errors::error::{AriesVcxCoreError, VcxCoreResult};

use openssl::hash::{Hasher, MessageDigest};

pub fn hash(input: &[u8]) -> VcxCoreResult<Vec<u8>> {
    let mut hasher = Hash::new_context()?;
    hasher.update(input)?;
    Ok(hasher.finish().map(|b| b.to_vec())?)
}

pub struct Hash {}

impl Hash {
    pub fn new_context() -> VcxCoreResult<Hasher> {
        Ok(Hasher::new(MessageDigest::sha256())?)
    }

    // pub fn hash_leaf<T>(leaf: &T) -> VcxCoreResult<Vec<u8>>
    // where
    //     T: Hashable,
    // {
    //     let mut ctx = Hash::new_context()?;
    //     ctx.update(&[0x00])?;
    //     leaf.update_context(&mut ctx)?;
    //     Ok(ctx.finish().map(|b| b.to_vec())?)
    // }

    // pub fn hash_nodes<T>(left: &T, right: &T) -> VcxCoreResult<Vec<u8>>
    // where
    //     T: Hashable,
    // {
    //     let mut ctx = Hash::new_context()?;
    //     ctx.update(&[0x01])?;
    //     left.update_context(&mut ctx)?;
    //     right.update_context(&mut ctx)?;
    //     Ok(ctx.finish().map(|b| b.to_vec())?)
    // }
}

/// The type of values stored in a `MerkleTree` must implement
/// this trait, in order for them to be able to be fed
/// to a Ring `Context` when computing the hash of a leaf.
///
/// A default instance for types that already implements
/// `AsRef<[u8]>` is provided.
///
/// ## Example
///
/// Here is an example of how to implement `Hashable` for a type
/// that does not (or cannot) implement `AsRef<[u8]>`:
///
/// ```ignore
/// impl Hashable for PublicKey {
///     fn update_context(&self, context: &mut Hasher) -> Result<(), CommonError> {
///         let bytes: Vec<u8> = self.to_bytes();
///         Ok(context.update(&bytes)?)
///     }
/// }
/// ```
pub trait Hashable {
    /// Update the given `context` with `self`.
    ///
    /// See `openssl::hash::Hasher::update` for more information.
    fn update_context(&self, context: &mut Hasher) -> VcxCoreResult<()>;
}

impl<T: AsRef<[u8]>> Hashable for T {
    fn update_context(&self, context: &mut Hasher) -> VcxCoreResult<()> {
        Ok(context.update(self.as_ref())?)
    }
}
