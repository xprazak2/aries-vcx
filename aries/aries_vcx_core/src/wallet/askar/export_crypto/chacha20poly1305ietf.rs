use std::{
    cmp,
    io::{self, Read, Write},
};

use sodiumoxide::{
    crypto::{
        aead::{
            chacha20poly1305::KEYBYTES,
            chacha20poly1305_ietf::{self, Key, Nonce},
        },
        pwhash::Salt,
    },
    utils,
};

use super::{key_derivation_method::KeyDerivationMethod, pwhash::pwhash};
use crate::{
    errors::error::VcxCoreResult,
    wallet::askar::{AriesVcxCoreError, AriesVcxCoreErrorKind},
};

pub fn derive_key(
    passphrase: &str,
    salt: &Salt,
    key_derivation_method: &KeyDerivationMethod,
) -> VcxCoreResult<chacha20poly1305_ietf::Key> {
    let mut key_bytes = [0u8; KEYBYTES];

    pwhash(
        &mut key_bytes,
        passphrase.as_bytes(),
        salt,
        key_derivation_method,
    )
    .map_err(|err| err.extend("Can't derive key"))?;

    Ok(chacha20poly1305_ietf::Key(key_bytes))
}

pub struct Writer<W: Write> {
    buffer: Vec<u8>,
    chunk_size: usize,
    key: chacha20poly1305_ietf::Key,
    nonce: Nonce,
    inner: W,
}

fn increment_nonce(nonce: &mut Nonce) {
    utils::increment_le(&mut nonce.0)
}

impl<W: Write> Writer<W> {
    pub fn new(inner: W, key: chacha20poly1305_ietf::Key, nonce: Nonce, chunk_size: usize) -> Self {
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

pub struct Reader<R: Read> {
    rest_buffer: Vec<u8>,
    chunk_buffer: Vec<u8>,
    key: Key,
    nonce: Nonce,
    inner: R,
}

impl<R: Read> Reader<R> {
    pub fn new(inner: R, key: Key, nonce: Nonce, chunk_size: usize) -> Self {
        Reader {
            rest_buffer: Vec::new(),
            chunk_buffer: vec![0; chunk_size + chacha20poly1305_ietf::TAGBYTES],
            key,
            nonce,
            inner,
        }
    }

    #[allow(unused)]
    pub fn into_inner(self) -> R {
        self.inner
    }

    fn _read_chunk(&mut self) -> io::Result<usize> {
        let mut read = 0;

        while read < self.chunk_buffer.len() {
            match self.inner.read(&mut self.chunk_buffer[read..]) {
                Ok(0) => break,
                Ok(n) => read += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        if read == 0 {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "No more crypto chucks to consume",
            ))
        } else {
            Ok(read)
        }
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut pos = 0;

        // Consume from rest buffer
        if !self.rest_buffer.is_empty() {
            let to_copy = cmp::min(self.rest_buffer.len(), buf.len() - pos);
            buf[pos..pos + to_copy].copy_from_slice(&self.rest_buffer[..to_copy]);
            pos += to_copy;
            self.rest_buffer.drain(..to_copy);
        }

        // Consume from chunks
        while pos < buf.len() {
            let chunk_size = self._read_chunk()?;

            let chunk = decrypt(&self.chunk_buffer[..chunk_size], &self.key, &self.nonce).map_err(
                |_| io::Error::new(io::ErrorKind::InvalidData, "Invalid data in crypto chunk"),
            )?;

            increment_nonce(&mut self.nonce);

            let to_copy = cmp::min(chunk.len(), buf.len() - pos);
            buf[pos..pos + to_copy].copy_from_slice(&chunk[..to_copy]);
            pos += to_copy;

            // Save rest in rest buffer
            if pos == buf.len() && to_copy < chunk.len() {
                self.rest_buffer.extend(&chunk[to_copy..]);
            }
        }

        Ok(buf.len())
    }
}

pub fn decrypt(data: &[u8], key: &Key, nonce: &Nonce) -> VcxCoreResult<Vec<u8>> {
    chacha20poly1305_ietf::open(data, None, &nonce, &key).map_err(|err| {
        AriesVcxCoreError::from_msg(AriesVcxCoreErrorKind::InvalidInput, "failed to decrypt")
    })
}
