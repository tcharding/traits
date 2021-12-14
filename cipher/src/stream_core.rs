use crate::StreamCipherError;
use core::convert::{TryFrom, TryInto};
use crypto_common::{Block, BlockSizeUser};
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
use inout::{ChunkProc, InOutBuf};

/// Block-level synchronous stream ciphers.
pub trait StreamCipherCore: BlockSizeUser + Sized {
    /// Return number of remaining blocks before cipher wraps around.
    ///
    /// Returns `None` if number of remaining blocks can not be computed
    /// (e.g. in ciphers based on the sponge construction) or it's too big
    /// to fit into `usize`.
    fn remaining_blocks(&self) -> Option<usize>;

    /// Process `blocks` with generated keystream blocks.
    ///
    /// WARNING: this method does not check number of remaining blocks!
    fn process_with_keystream_blocks<B: ChunkProc<Block<Self>>>(
        &mut self,
        blocks: B,
        body: impl FnMut(B, &mut [Block<Self>]),
    );

    /// Apply keystream blocks with post hook.
    ///
    /// WARNING: this method does not check number of remaining blocks!
    fn apply_keystream_blocks(
        &mut self,
        blocks: InOutBuf<'_, Block<Self>>,
        mut post_fn: impl FnMut(&[Block<Self>]),
    ) {
        self.process_with_keystream_blocks(blocks, |mut chunk, keystream| {
            apply_ks(chunk.reborrow(), keystream);
            post_fn(chunk.get_out());
        });
    }

    /// Write keystream blocks to `buf`.
    ///
    /// WARNING: this method does not check number of remaining blocks!
    fn write_keystream_blocks(&mut self, buf: &mut [Block<Self>]) {
        self.process_with_keystream_blocks(buf, |chunk, keystream| {
            assert_eq!(chunk.len(), keystream.len());
            for (a, b) in chunk.iter_mut().zip(keystream.iter()) {
                a.copy_from_slice(b);
            }
        });
    }

    /// Try to apply keystream to data not divided into blocks.
    ///
    /// Consumes cipher since it may consume final keystream block only
    /// partially.
    ///
    /// Returns an error if number of remaining blocks is not sufficient
    /// for processing the input data.
    fn try_apply_keystream_partial(
        mut self,
        mut buf: InOutBuf<'_, u8>,
    ) -> Result<(), StreamCipherError> {
        if let Some(rem) = self.remaining_blocks() {
            let blocks = if buf.len() % Self::BlockSize::USIZE == 0 {
                buf.len() % Self::BlockSize::USIZE
            } else {
                buf.len() % Self::BlockSize::USIZE + 1
            };
            if blocks > rem {
                return Err(StreamCipherError);
            }
        }

        if buf.len() > Self::BlockSize::USIZE {
            let (blocks, tail) = buf.into_chunks();
            self.apply_keystream_blocks(blocks, |_| {});
            buf = tail;
        }
        let n = buf.len();
        if n == 0 {
            return Ok(());
        }
        let mut block = Block::<Self>::default();
        block[..n].copy_from_slice(buf.reborrow().get_in());
        let mut t = InOutBuf::from_mut(&mut block);
        self.apply_keystream_blocks(t.reborrow(), |_| {});
        buf.get_out().copy_from_slice(&block[..n]);
        Ok(())
    }

    /// Try to apply keystream to data not divided into blocks.
    ///
    /// Consumes cipher since it may consume final keystream block only
    /// partially.
    ///
    /// # Panics
    /// If number of remaining blocks is not sufficient for processing the
    /// input data.
    fn apply_keystream_partial(self, buf: InOutBuf<'_, u8>) {
        self.try_apply_keystream_partial(buf).unwrap()
    }
}

// note: unfortunately, currently we can not write blanket impls of
// `BlockEncryptMut` and `BlockDecryptMut` for `T: StreamCipherCore`
// since it requires mutually exlusive traits, see:
// https://github.com/rust-lang/rfcs/issues/1053

/// Counter type usable with [`StreamCipherCore`].
///
/// This trait is implemented for `i32`, `u32`, `u64`, `u128`, and `usize`.
/// It's not intended to be implemented in third-party crates, but doing so
/// is not forbidden.
pub trait Counter:
    TryFrom<i32>
    + TryFrom<u32>
    + TryFrom<u64>
    + TryFrom<u128>
    + TryFrom<usize>
    + TryInto<i32>
    + TryInto<u32>
    + TryInto<u64>
    + TryInto<u128>
    + TryInto<usize>
{
}

/// Block-level seeking trait for stream ciphers.
pub trait StreamCipherSeekCore: StreamCipherCore {
    /// Counter type used inside stream cipher.
    type Counter: Counter;

    /// Get current block position.
    fn get_block_pos(&self) -> Self::Counter;

    /// Set block position.
    fn set_block_pos(&mut self, pos: Self::Counter);
}

macro_rules! impl_counter {
    {$($t:ty )*} => {
        $( impl Counter for $t { } )*
    };
}

impl_counter! { u32 u64 u128 }

type B<N> = GenericArray<u8, N>;

fn apply_ks<N: ArrayLength<u8>>(blocks: InOutBuf<'_, B<N>>, ks: &[B<N>]) {
    use core::ptr;

    assert_eq!(blocks.len(), ks.len());
    let n = blocks.len();
    unsafe {
        let (in_ptr, out_ptr) = blocks.into_raw();
        let ks_ptr = ks.as_ptr();
        for i in 0..n {
            let a = ptr::read(in_ptr.add(i));
            let b = ptr::read(ks_ptr.add(i));
            let mut res = GenericArray::<u8, N>::default();
            for j in 0..N::USIZE {
                res[j] = a[j] ^ b[j];
            }
            ptr::write(out_ptr.add(i), res);
        }
    }
}
