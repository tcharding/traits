//! Traits used to define functionality of [block ciphers][1] and [modes of operation][2].
//!
//! # About block ciphers
//!
//! Block ciphers are keyed, deterministic permutations of a fixed-sized input
//! "block" providing a reversible transformation to/from an encrypted output.
//! They are one of the fundamental structural components of [symmetric cryptography][3].
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher
//! [2]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
//! [3]: https://en.wikipedia.org/wiki/Symmetric-key_algorithm

use crate::{ParBlocks, ParBlocksSizeUser};
use inout::{InOut, InOutBuf, NotEqualError};

pub use crypto_common::{generic_array::ArrayLength, typenum::Unsigned, Block, BlockSizeUser};

/// Marker trait for block ciphers.
pub trait BlockCipher: BlockSizeUser {}

pub trait BlockBackend: ParBlocksSizeUser {
    fn proc_block(&mut self, block: InOut<'_, Block<Self>>);

    #[inline(always)]
    fn proc_par_blocks(&mut self, mut blocks: InOut<'_, ParBlocks<Self>>) {
        for i in 0..Self::ParBlocksSize::USIZE {
            self.proc_block(blocks.get(i));
        }
    }

    #[inline(always)]
    fn proc_tail_blocks(&mut self, blocks: InOutBuf<'_, Block<Self>>) {
        assert!(blocks.len() < Self::ParBlocksSize::USIZE);
        for block in blocks {
            self.proc_block(block);
        }
    }
}

pub trait BlockClosure: BlockSizeUser {
    fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B);
}

/// Encrypt-only functionality for block ciphers.
pub trait BlockEncrypt: BlockSizeUser + Sized {
    fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>);

    /// Encrypt single `inout` block.
    #[inline]
    fn encrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        self.encrypt_with_backend(BlockCtx { block });
    }

    /// Encrypt `inout` blocks.
    #[inline]
    fn encrypt_blocks_inout(&self, blocks: InOutBuf<'_, Block<Self>>) {
        self.encrypt_with_backend(BlocksCtx { blocks });
    }

    /// Encrypt single block in-place.
    #[inline]
    fn encrypt_block(&self, block: &mut Block<Self>) {
        let block = block.into();
        self.encrypt_with_backend(BlockCtx { block });
    }

    /// Encrypt `in_block` and write result to `out_block`.
    #[inline]
    fn encrypt_block_b2b(&self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        let block = (in_block, out_block).into();
        self.encrypt_with_backend(BlockCtx { block });
    }

    /// Encrypt blocks in-place.
    #[inline]
    fn encrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        let blocks = blocks.into();
        self.encrypt_with_backend(BlocksCtx { blocks });
    }

    /// Encrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn encrypt_blocks_b2b(
        &self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks)
            .map(|blocks| self.encrypt_with_backend(BlocksCtx { blocks }))
    }
}

/// Decrypt-only functionality for block ciphers.
pub trait BlockDecrypt: BlockSizeUser {
    fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>);

    /// Decrypt single `inout` block.
    #[inline]
    fn decrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        self.decrypt_with_backend(BlockCtx { block });
    }

    /// Decrypt `inout` blocks.
    #[inline]
    fn decrypt_blocks_inout(&self, blocks: InOutBuf<'_, Block<Self>>) {
        self.decrypt_with_backend(BlocksCtx { blocks });
    }

    /// Decrypt single block in-place.
    #[inline]
    fn decrypt_block(&self, block: &mut Block<Self>) {
        let block = block.into();
        self.decrypt_with_backend(BlockCtx { block });
    }

    /// Decrypt `in_block` and write result to `out_block`.
    #[inline]
    fn decrypt_block_b2b(&self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        let block = (in_block, out_block).into();
        self.decrypt_with_backend(BlockCtx { block });
    }

    /// Decrypt blocks in-place.
    #[inline]
    fn decrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        let blocks = blocks.into();
        self.decrypt_with_backend(BlocksCtx { blocks });
    }

    /// Decrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn decrypt_blocks_b2b(
        &self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks)
            .map(|blocks| self.decrypt_with_backend(BlocksCtx { blocks }))
    }
}

/// Encrypt-only functionality for block ciphers and modes with mutable access to `self`.
///
/// The main use case for this trait is blocks modes, but it also can be used
/// for hardware cryptographic engines which require `&mut self` access to an
/// underlying hardware peripheral.
pub trait BlockEncryptMut: BlockSizeUser {
    fn encrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>);

    /// Encrypt single `inout` block.
    #[inline]
    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.encrypt_with_backend_mut(BlockCtx { block });
    }

    /// Encrypt `inout` blocks.
    #[inline]
    fn encrypt_blocks_inout_mut(&mut self, blocks: InOutBuf<'_, Block<Self>>) {
        self.encrypt_with_backend_mut(BlocksCtx { blocks });
    }

    /// Encrypt single block in-place.
    #[inline]
    fn encrypt_block_mut(&mut self, block: &mut Block<Self>) {
        let block = block.into();
        self.encrypt_with_backend_mut(BlockCtx { block });
    }

    /// Encrypt `in_block` and write result to `out_block`.
    #[inline]
    fn encrypt_block_b2b_mut(&mut self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        let block = (in_block, out_block).into();
        self.encrypt_with_backend_mut(BlockCtx { block });
    }

    /// Encrypt blocks in-place.
    #[inline]
    fn encrypt_blocks_mut(&mut self, blocks: &mut [Block<Self>]) {
        let blocks = blocks.into();
        self.encrypt_with_backend_mut(BlocksCtx { blocks });
    }

    /// Encrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn encrypt_blocks_b2b_mut(
        &mut self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks)
            .map(|blocks| self.encrypt_with_backend_mut(BlocksCtx { blocks }))
    }
}

/// Decrypt-only functionality for block ciphers and modes with mutable access to `self`.
///
/// The main use case for this trait is blocks modes, but it also can be used
/// for hardware cryptographic engines which require `&mut self` access to an
/// underlying hardware peripheral.
pub trait BlockDecryptMut: BlockSizeUser {
    fn decrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>);

    /// Decrypt single `inout` block.
    #[inline]
    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.decrypt_with_backend_mut(BlockCtx { block });
    }

    /// Decrypt `inout` blocks.
    #[inline]
    fn decrypt_blocks_inout_mut(&mut self, blocks: InOutBuf<'_, Block<Self>>) {
        self.decrypt_with_backend_mut(BlocksCtx { blocks });
    }

    /// Decrypt single block in-place.
    #[inline]
    fn decrypt_block_mut(&mut self, block: &mut Block<Self>) {
        let block = block.into();
        self.decrypt_with_backend_mut(BlockCtx { block });
    }

    /// Decrypt `in_block` and write result to `out_block`.
    #[inline]
    fn decrypt_block_b2b_mut(&mut self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        let block = (in_block, out_block).into();
        self.decrypt_with_backend_mut(BlockCtx { block });
    }

    /// Decrypt blocks in-place.
    #[inline]
    fn decrypt_blocks_mut(&mut self, blocks: &mut [Block<Self>]) {
        let blocks = blocks.into();
        self.decrypt_with_backend_mut(BlocksCtx { blocks });
    }

    /// Decrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn decrypt_blocks_b2b_mut(
        &mut self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks)
            .map(|blocks| self.decrypt_with_backend_mut(BlocksCtx { blocks }))
    }
}

impl<Alg: BlockEncrypt> BlockEncryptMut for Alg {
    fn encrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        self.encrypt_with_backend(f);
    }
}

impl<Alg: BlockDecrypt> BlockDecryptMut for Alg {
    fn decrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        self.decrypt_with_backend(f);
    }
}

impl<Alg: BlockCipher> BlockCipher for &Alg {}

impl<Alg: BlockEncrypt> BlockEncrypt for &Alg {
    fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        Alg::encrypt_with_backend(self, f);
    }
}

impl<Alg: BlockDecrypt> BlockDecrypt for &Alg {
    fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        Alg::decrypt_with_backend(self, f);
    }
}

/// Closure used in methods which operate over separate blocks.
struct BlockCtx<'a, BS: ArrayLength<u8>> {
    block: InOut<'a, Block<Self>>,
}

impl<'a, BS: ArrayLength<u8>> BlockSizeUser for BlockCtx<'a, BS> {
    type BlockSize = BS;
}

impl<'a, BS: ArrayLength<u8>> BlockClosure for BlockCtx<'a, BS> {
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = BS>>(self, backend: &mut B) {
        backend.proc_block(self.block);
    }
}

/// Closure used in methods which operate over slice of blocks.
struct BlocksCtx<'a, BS: ArrayLength<u8>> {
    blocks: InOutBuf<'a, Block<Self>>,
}

impl<'a, BS: ArrayLength<u8>> BlockSizeUser for BlocksCtx<'a, BS> {
    type BlockSize = BS;
}

impl<'a, BS: ArrayLength<u8>> BlockClosure for BlocksCtx<'a, BS> {
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = BS>>(self, backend: &mut B) {
        if B::ParBlocksSize::USIZE > 1 {
            let (chunks, tail) = self.blocks.into_chunks();
            for chunk in chunks {
                backend.proc_par_blocks(chunk);
            }
            backend.proc_tail_blocks(tail);
        } else {
            for block in self.blocks {
                backend.proc_block(block);
            }
        }
    }
}

/// Implement simple block backend
#[macro_export]
macro_rules! impl_simple_block_encdec {
    (
        <$($N:ident$(:$b0:ident$(+$b:ident)*)?),*>
        $cipher:ident, $block_size:ty, $state:ident, $block:ident,
        encrypt: $enc_block:block
        decrypt: $dec_block:block
    ) => {
        impl<$($N$(:$b0$(+$b)*)?),*> $crate::BlockSizeUser for $cipher<$($N),*> {
            type BlockSize = $block_size;
        }

        impl<$($N$(:$b0$(+$b)*)?),*> $crate::BlockEncrypt for $cipher<$($N),*> {
            fn encrypt_with_backend(&self, f: impl $crate::BlockClosure<BlockSize = $block_size>) {
                struct EncBack<'a, $($N$(:$b0$(+$b)*)?),* >(&'a $cipher<$($N),*>);

                impl<'a, $($N$(:$b0$(+$b)*)?),* > $crate::BlockSizeUser for EncBack<'a, $($N),*> {
                    type BlockSize = $block_size;
                }

                impl<'a, $($N$(:$b0$(+$b)*)?),* > $crate::ParBlocksSizeUser for EncBack<'a, $($N),*> {
                    type ParBlocksSize = $crate::consts::U1;
                }

                impl<'a, $($N$(:$b0$(+$b)*)?),* > $crate::BlockBackend for EncBack<'a, $($N),*> {
                    #[inline(always)]
                    fn proc_block(
                        &mut self,
                        mut $block: $crate::inout::InOut<'_, $crate::Block<Self>>
                    ) {
                        let $state: &$cipher<$($N),*> = self.0;
                        $enc_block
                    }
                }

                f.call(&mut EncBack(self))
            }
        }

        impl<$($N$(:$b0$(+$b)*)?),*> $crate::BlockDecrypt for $cipher<$($N),*> {
            fn decrypt_with_backend(&self, f: impl $crate::BlockClosure<BlockSize = $block_size>) {
                struct DecBack<'a, $($N$(:$b0$(+$b)*)?),* >(&'a $cipher<$($N),*>);

                impl<'a, $($N$(:$b0$(+$b)*)?),* > $crate::BlockSizeUser for DecBack<'a, $($N),*> {
                    type BlockSize = $block_size;
                }

                impl<'a, $($N$(:$b0$(+$b)*)?),* > $crate::ParBlocksSizeUser for DecBack<'a, $($N),*> {
                    type ParBlocksSize = $crate::consts::U1;
                }

                impl<'a, $($N$(:$b0$(+$b)*)?),* > $crate::BlockBackend for DecBack<'a, $($N),*> {
                    #[inline(always)]
                    fn proc_block(
                        &mut self,
                        mut $block: $crate::inout::InOut<'_, $crate::Block<Self>>
                    ) {
                        let $state: &$cipher<$($N),*> = self.0;
                        $dec_block
                    }
                }

                f.call(&mut DecBack(self))
            }
        }
    };
    (
        $cipher:ident, $block_size:ty, $state:ident, $block:ident,
        encrypt: $enc_block:block
        decrypt: $dec_block:block
    ) => {
        $crate::impl_simple_block_encdec!(
            <> $cipher, $block_size, $state, $block,
            encrypt: $enc_block
            decrypt: $dec_block
        );
    };
}
