use std::io::{self, Write};

use sodiumoxide::{
    crypto::aead::chacha20poly1305_ietf::{self, Key, Nonce},
    utils,
};

pub struct Writer<W: Write> {
    buffer: Vec<u8>,
    chunk_size: usize,
    key: Key,
    nonce: Nonce,
    inner: W,
}

fn increment_nonce(nonce: &mut Nonce) {
    utils::increment_le(&mut nonce.0)
}

impl<W: Write> Writer<W> {
    pub fn new(inner: W, key: Key, nonce: Nonce, chunk_size: usize) -> Self {
        Writer {
            buffer: Vec::new(),
            chunk_size,
            key,
            nonce,
            inner,
        }
    }

    #[allow(unused)]
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.write_all(buf)?; // TODO: Small optimizations are possible

        let mut chunk_start = 0;

        while self.buffer.len() >= chunk_start + self.chunk_size {
            let chunk = &self.buffer[chunk_start..chunk_start + self.chunk_size];
            self.inner
                .write_all(&encrypt(chunk, &self.key, &self.nonce))?;
            increment_nonce(&mut self.nonce);
            chunk_start += self.chunk_size;
        }

        if chunk_start > 0 {
            self.buffer.drain(..chunk_start);
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            self.inner
                .write_all(&encrypt(&self.buffer, &self.key, &self.nonce))?;
            increment_nonce(&mut self.nonce);
        }

        self.buffer.flush()
    }
}

pub fn encrypt(data: &[u8], key: &Key, nonce: &Nonce) -> Vec<u8> {
    chacha20poly1305_ietf::seal(data, None, &nonce, &key)
}
