//! BGW Broadcast Key Encapsulation Mechanism wrapper.
//!
//! ## File format (v2 — streaming)
//!
//! ```text
//! [4 bytes: magic b"HMT2"]
//! [bincode: BroadcastHeader]          ← small metadata, read first
//! [u32: chunk_0_ciphertext_len][chunk_0_bytes]
//! [u32: chunk_1_ciphertext_len][chunk_1_bytes]
//! ...                                 ← read until EOF
//! ```
//!
//! Encrypt pipeline: input → zstd::Encoder(mt) → ChunkEncryptor → File
//! Decrypt pipeline: File → ChunkDecryptor → zstd::Decoder → output
//!
//! Revocation = exclude user from the recipient set at encryption time.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use crate::error::{HimitsuError, Result};
use std::ffi::CString;
use std::io::{self, Read, Write};

/// Maximum number of users in the system.
pub const MAX_USERS: usize = 1000;

/// 1 MiB chunk size for AES-GCM.
pub const CHUNK_SIZE: usize = 1 << 20;

/// File format magic bytes.
pub const MAGIC: [u8; 4] = *b"HMT2";

/// Type-A pairing parameters for PBC.
const PAIRING_PARAMS: &str = "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1\n";

/// File header — small, written/read first before any chunk data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastHeader {
    /// Serialized BGW header elements.
    pub header: Vec<Vec<u8>>,
    /// Indices of authorized users (required by BGW decryption math).
    pub recipients: Vec<u32>,
    /// Base nonce (8 bytes) for chunked AES-GCM.
    pub nonce: Vec<u8>,
    /// Plaintext chunk size before AES-GCM encryption.
    pub chunk_size: usize,
    /// Whether the plaintext is a tar archive (encrypted folder).
    pub is_folder: bool,
    /// Original filename (preserved across encrypt/decrypt).
    pub filename: Option<String>,
}

/// Live BGW system handle — NOT serializable.
pub struct BgwSystem {
    gps: pbc_bkem_sys::bkem_global_params_t,
    sys: pbc_bkem_sys::bkem_system_t,
}

unsafe impl Send for BgwSystem {}
unsafe impl Sync for BgwSystem {}

impl BgwSystem {
    /// Generate a fresh BGW system (first launch only).
    pub fn generate() -> Result<Self> {
        let params_cstr = CString::new(PAIRING_PARAMS)
            .map_err(|e| HimitsuError::Broadcast(format!("Params: {e}")))?;

        unsafe {
            let mut gps: pbc_bkem_sys::bkem_global_params_t = std::ptr::null_mut();
            pbc_bkem_sys::setup_global_system(
                &mut gps,
                params_cstr.as_ptr(),
                MAX_USERS as i32,
            );
            if gps.is_null() {
                return Err(HimitsuError::Broadcast("setup_global_system failed".into()));
            }

            let mut sys: pbc_bkem_sys::bkem_system_t = std::ptr::null_mut();
            pbc_bkem_sys::setup(&mut sys, gps);
            if sys.is_null() {
                pbc_bkem_sys::free_global_params(gps);
                return Err(HimitsuError::Broadcast("setup failed".into()));
            }

            let n = (*gps).N;
            let a = (*gps).A;
            let b = (*gps).B;
            tracing::info!(N = n, A = a, B = b, "BGW system generated");

            Ok(BgwSystem { gps, sys })
        }
    }

    /// Serialize all key material to bytes for persistent storage.
    ///
    /// Format: [A:u32][B:u32][N:u32]
    ///         [g_bytes_len:u32][g_bytes...]
    ///         [g_i count:u32]([len:u32][bytes...])*
    ///         [v_i count:u32]([len:u32][bytes...])*
    ///         [d_i count:u32]([len:u32][bytes...])*
    pub fn serialize(&self) -> Result<Vec<u8>> {
        unsafe {
            let a = (*self.gps).A as u32;
            let b = (*self.gps).B as u32;
            let n = (*self.gps).N as u32;
            let pk = &*(*self.sys).PK;

            let mut out = Vec::new();
            out.extend_from_slice(&a.to_le_bytes());
            out.extend_from_slice(&b.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());

            serialize_element(&mut out, pk.g.as_ptr() as *mut _);

            let num_gi = (2 * b) as usize;
            out.extend_from_slice(&(num_gi as u32).to_le_bytes());
            for i in 0..num_gi {
                let elem = pk.g_i.offset(i as isize) as *mut pbc_bkem_sys::element_s;
                serialize_element(&mut out, elem);
            }

            out.extend_from_slice(&a.to_le_bytes());
            for i in 0..a as usize {
                let elem = pk.v_i.offset(i as isize) as *mut pbc_bkem_sys::element_s;
                serialize_element(&mut out, elem);
            }

            out.extend_from_slice(&n.to_le_bytes());
            for i in 0..n as usize {
                let elem = (*self.sys).d_i.offset(i as isize) as *mut pbc_bkem_sys::element_s;
                serialize_element(&mut out, elem);
            }

            Ok(out)
        }
    }

    /// Reconstruct a BGW system from serialized bytes (app restart).
    pub fn load(data: &[u8]) -> Result<Self> {
        let params_cstr = CString::new(PAIRING_PARAMS)
            .map_err(|e| HimitsuError::Broadcast(format!("Params: {e}")))?;

        unsafe {
            let mut gps: pbc_bkem_sys::bkem_global_params_t = std::ptr::null_mut();
            pbc_bkem_sys::setup_global_system(&mut gps, params_cstr.as_ptr(), MAX_USERS as i32);
            if gps.is_null() {
                return Err(HimitsuError::Broadcast("setup_global_system failed".into()));
            }

            let mut cursor = 0usize;

            let a = read_u32(data, &mut cursor);
            let b = read_u32(data, &mut cursor);
            let n = read_u32(data, &mut cursor);

            let sys = libc::malloc(std::mem::size_of::<pbc_bkem_sys::bkem_system_s>())
                as pbc_bkem_sys::bkem_system_t;
            let pk = libc::malloc(std::mem::size_of::<pbc_bkem_sys::pubkey_s>())
                as pbc_bkem_sys::pubkey_t;
            (*sys).PK = pk;

            pbc_bkem_sys::himitsu_element_init_G1(
                (*pk).g.as_mut_ptr(), (*gps).pairing.as_mut_ptr()
            );
            deserialize_element((*pk).g.as_mut_ptr(), data, &mut cursor);

            let num_gi = read_u32(data, &mut cursor) as usize;
            (*pk).g_i = libc::malloc(num_gi * std::mem::size_of::<pbc_bkem_sys::element_t>())
                as *mut pbc_bkem_sys::element_t;
            for i in 0..num_gi {
                let elem = (*(*pk).g_i.offset(i as isize)).as_mut_ptr();
                pbc_bkem_sys::himitsu_element_init_G1(elem, (*gps).pairing.as_mut_ptr());
                deserialize_element(elem, data, &mut cursor);
            }

            let num_vi = read_u32(data, &mut cursor) as usize;
            (*pk).v_i = libc::malloc(num_vi * std::mem::size_of::<pbc_bkem_sys::element_t>())
                as *mut pbc_bkem_sys::element_t;
            for i in 0..num_vi {
                let elem = (*(*pk).v_i.offset(i as isize)).as_mut_ptr();
                pbc_bkem_sys::himitsu_element_init_G1(elem, (*gps).pairing.as_mut_ptr());
                deserialize_element(elem, data, &mut cursor);
            }

            let num_di = read_u32(data, &mut cursor) as usize;
            (*sys).d_i = libc::malloc(num_di * std::mem::size_of::<pbc_bkem_sys::element_t>())
                as *mut pbc_bkem_sys::element_t;
            for i in 0..num_di {
                let elem = (*(*sys).d_i.offset(i as isize)).as_mut_ptr();
                pbc_bkem_sys::himitsu_element_init_G1(elem, (*gps).pairing.as_mut_ptr());
                deserialize_element(elem, data, &mut cursor);
            }

            tracing::info!(N = n, A = a, B = b, "BGW system loaded from DB");

            Ok(BgwSystem { gps, sys })
        }
    }

    pub fn num_users(&self) -> usize {
        unsafe { (*self.gps).N as usize }
    }

    /// Export a user's private key as bytes.
    pub fn export_user_key(&self, index: u32) -> Result<Vec<u8>> {
        let n = self.num_users();
        if index as usize >= n {
            return Err(HimitsuError::Broadcast(format!(
                "User index {index} out of range (max {n})"
            )));
        }
        unsafe {
            let elem = (*self.sys).d_i.offset(index as isize) as *mut pbc_bkem_sys::element_s;
            let len = pbc_bkem_sys::himitsu_element_length_in_bytes(elem) as usize;
            let mut buf = vec![0u8; len];
            pbc_bkem_sys::himitsu_element_to_bytes(buf.as_mut_ptr(), elem);
            Ok(buf)
        }
    }

    /// Encrypt: produce a BGW header + AES key for a set of recipients.
    pub fn encapsulate(&self, recipients: &[u32]) -> Result<(Vec<Vec<u8>>, [u8; 32])> {
        if recipients.is_empty() {
            return Err(HimitsuError::Broadcast("Empty recipient set".into()));
        }

        let mut s: Vec<i32> = recipients.iter().map(|&r| r as i32).collect();

        unsafe {
            let mut keypair: pbc_bkem_sys::keypair_t = std::ptr::null_mut();
            pbc_bkem_sys::get_encryption_key(
                &mut keypair,
                s.as_mut_ptr(),
                s.len() as i32,
                self.sys,
                self.gps,
            );
            if keypair.is_null() {
                return Err(HimitsuError::Broadcast("get_encryption_key failed".into()));
            }

            let k_ptr = (*keypair).K.as_mut_ptr();
            let k_len = pbc_bkem_sys::himitsu_element_length_in_bytes(k_ptr) as usize;
            let mut k_buf = vec![0u8; k_len];
            pbc_bkem_sys::himitsu_element_to_bytes(k_buf.as_mut_ptr(), k_ptr);
            let aes_key: [u8; 32] = Sha256::digest(&k_buf).into();

            let a = (*self.gps).A as usize;
            let num_hdr = a + 1;
            let mut header = Vec::with_capacity(num_hdr);
            for i in 0..num_hdr {
                let elem = (*keypair).HDR.offset(i as isize) as *mut pbc_bkem_sys::element_s;
                let elen = pbc_bkem_sys::himitsu_element_length_in_bytes(elem) as usize;
                let mut ebuf = vec![0u8; elen];
                pbc_bkem_sys::himitsu_element_to_bytes(ebuf.as_mut_ptr(), elem);
                header.push(ebuf);
            }

            for i in 0..num_hdr {
                pbc_bkem_sys::himitsu_element_clear(
                    (*keypair).HDR.offset(i as isize) as *mut pbc_bkem_sys::element_s
                );
            }
            pbc_bkem_sys::himitsu_element_clear(k_ptr);
            libc::free((*keypair).HDR as *mut libc::c_void);
            libc::free(keypair as *mut libc::c_void);

            Ok((header, aes_key))
        }
    }

    /// Decrypt: recover AES key from a BGW header using a user's private key.
    ///
    /// `d_i_bytes` is the serialized PBC element for this user's private key.
    /// The recipient set S is required by the BGW math (used to compute the
    /// decryption pairing). If the user is not in S, `get_decryption_key`
    /// produces an incorrect K and AES-GCM will reject the ciphertext.
    pub fn decapsulate(
        &self,
        user_index: u32,
        d_i_bytes: &[u8],
        recipients: &[u32],
        header: &[Vec<u8>],
    ) -> Result<[u8; 32]> {
        let a = unsafe { (*self.gps).A as usize };
        if header.len() != a + 1 {
            return Err(HimitsuError::Decryption(format!(
                "Header has {} elements, expected {}",
                header.len(), a + 1
            )));
        }

        unsafe {
            // Deserialize the user's private key element
            let mut d_i = std::mem::zeroed::<pbc_bkem_sys::element_t>();
            pbc_bkem_sys::himitsu_element_init_G1(
                d_i.as_mut_ptr(),
                (*self.gps).pairing.as_mut_ptr(),
            );
            pbc_bkem_sys::himitsu_element_from_bytes(
                d_i.as_mut_ptr(),
                d_i_bytes.as_ptr() as *mut _,
            );

            // Deserialize header elements
            let hdr_raw = libc::malloc(
                header.len() * std::mem::size_of::<pbc_bkem_sys::element_t>()
            ) as *mut pbc_bkem_sys::element_t;

            for (i, hdr_bytes) in header.iter().enumerate() {
                let elem = (*hdr_raw.offset(i as isize)).as_mut_ptr();
                pbc_bkem_sys::himitsu_element_init_G1(
                    elem,
                    (*self.gps).pairing.as_mut_ptr(),
                );
                pbc_bkem_sys::himitsu_element_from_bytes(elem, hdr_bytes.as_ptr() as *mut _);
            }

            let mut s: Vec<i32> = recipients.iter().map(|&r| r as i32).collect();

            let mut k = std::mem::zeroed::<pbc_bkem_sys::element_t>();

            pbc_bkem_sys::get_decryption_key(
                k.as_mut_ptr(),
                self.gps,
                s.as_mut_ptr(),
                s.len() as i32,
                user_index as i32,
                d_i.as_mut_ptr(),
                hdr_raw as *mut pbc_bkem_sys::element_t as *mut _,
                (*self.sys).PK,
            );

            let k_ptr = k.as_mut_ptr();
            let k_len = pbc_bkem_sys::himitsu_element_length_in_bytes(k_ptr) as usize;
            let mut k_buf = vec![0u8; k_len];
            pbc_bkem_sys::himitsu_element_to_bytes(k_buf.as_mut_ptr(), k_ptr);
            let aes_key: [u8; 32] = Sha256::digest(&k_buf).into();

            // Clean up
            pbc_bkem_sys::himitsu_element_clear(d_i.as_mut_ptr());
            pbc_bkem_sys::himitsu_element_clear(k_ptr);
            for i in 0..header.len() {
                pbc_bkem_sys::himitsu_element_clear((*hdr_raw.offset(i as isize)).as_mut_ptr());
            }
            libc::free(hdr_raw as *mut libc::c_void);

            Ok(aes_key)
        }
    }
}

impl Drop for BgwSystem {
    fn drop(&mut self) {
        unsafe {
            if !self.sys.is_null() {
                pbc_bkem_sys::free_bkem_system(self.sys, self.gps);
            }
            if !self.gps.is_null() {
                pbc_bkem_sys::free_global_params(self.gps);
            }
        }
    }
}

/// Write the file magic + header to a writer.
pub fn write_file_header<W: Write>(w: &mut W, hdr: &BroadcastHeader) -> Result<()> {
    w.write_all(&MAGIC)
        .map_err(|e| HimitsuError::Broadcast(format!("write magic: {e}")))?;
    bincode::serialize_into(w, hdr)
        .map_err(|e| HimitsuError::Broadcast(format!("write header: {e}")))?;
    Ok(())
}

/// Read and validate file magic + header from a reader.
pub fn read_file_header<R: Read>(r: &mut R) -> Result<BroadcastHeader> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)
        .map_err(|e| HimitsuError::Decryption(format!("read magic: {e}")))?;
    if magic != MAGIC {
        return Err(HimitsuError::Decryption(
            "Not a valid .himitsu file (bad magic)".into(),
        ));
    }
    bincode::deserialize_from(r)
        .map_err(|e| HimitsuError::Decryption(format!("read header: {e}")))
}

// ---------------------------------------------------------------------------
// Streaming encrypt: impl Write that buffers → AES-GCM encrypts → writes
// ---------------------------------------------------------------------------

/// Wraps a writer, buffering compressed data into CHUNK_SIZE windows,
/// AES-GCM encrypting each, and writing `[u32 len][ciphertext]` pairs.
pub struct ChunkEncryptor<W: Write> {
    writer: W,
    key: [u8; 32],
    base_nonce: [u8; 8],
    buffer: Vec<u8>,
    chunk_index: u32,
    chunk_size: usize,
}

impl<W: Write> ChunkEncryptor<W> {
    pub fn new(writer: W, key: [u8; 32], base_nonce: [u8; 8], chunk_size: usize) -> Self {
        Self {
            writer,
            key,
            base_nonce,
            buffer: Vec::with_capacity(chunk_size),
            chunk_index: 0,
            chunk_size,
        }
    }

    /// Encrypt and flush the current buffer as one chunk.
    fn flush_chunk(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        use aes_gcm::{Aes256Gcm, Key, Nonce};
        use aes_gcm::aead::{Aead, KeyInit};

        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);

        let mut nonce_buf = [0u8; 12];
        nonce_buf[..8].copy_from_slice(&self.base_nonce);
        nonce_buf[8..12].copy_from_slice(&self.chunk_index.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_buf);

        let ciphertext = cipher
            .encrypt(nonce, self.buffer.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("AES-GCM: {e}")))?;

        let len = ciphertext.len() as u32;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(&ciphertext)?;

        self.buffer.clear();
        self.chunk_index += 1;
        Ok(())
    }

    /// Flush any remaining data and return the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.flush_chunk()?;
        self.writer.flush()?;
        Ok(self.writer)
    }
}

impl<W: Write> Write for ChunkEncryptor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let space = self.chunk_size - self.buffer.len();
            let take = space.min(buf.len() - written);
            self.buffer.extend_from_slice(&buf[written..written + take]);
            written += take;
            if self.buffer.len() >= self.chunk_size {
                self.flush_chunk()?;
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Don't flush_chunk here — partial chunks are only flushed on finish().
        // This flush propagates to the inner writer for buffered I/O only.
        self.writer.flush()
    }
}

// ---------------------------------------------------------------------------
// Streaming decrypt: impl Read that reads chunks → AES-GCM decrypts → yields
// ---------------------------------------------------------------------------

/// Wraps a reader, reading `[u32 len][ciphertext]` pairs, AES-GCM decrypting
/// each, and yielding plaintext (compressed) bytes.
pub struct ChunkDecryptor<R: Read> {
    reader: R,
    key: [u8; 32],
    base_nonce: [u8; 8],
    buffer: Vec<u8>,
    buf_pos: usize,
    chunk_index: u32,
    done: bool,
}

impl<R: Read> ChunkDecryptor<R> {
    pub fn new(reader: R, key: [u8; 32], base_nonce: &[u8]) -> Self {
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&base_nonce[..8]);
        Self {
            reader,
            key,
            base_nonce: nonce,
            buffer: Vec::new(),
            buf_pos: 0,
            chunk_index: 0,
            done: false,
        }
    }

    /// Read and decrypt the next chunk into the internal buffer.
    fn load_next_chunk(&mut self) -> io::Result<bool> {
        // Read chunk length (u32 LE)
        let mut len_buf = [0u8; 4];
        match self.reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                self.done = true;
                return Ok(false);
            }
            Err(e) => return Err(e),
        }

        let ct_len = u32::from_le_bytes(len_buf) as usize;
        let mut ct_buf = vec![0u8; ct_len];
        self.reader.read_exact(&mut ct_buf)?;

        use aes_gcm::{Aes256Gcm, Key, Nonce};
        use aes_gcm::aead::{Aead, KeyInit};

        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);

        let mut nonce_buf = [0u8; 12];
        nonce_buf[..8].copy_from_slice(&self.base_nonce);
        nonce_buf[8..12].copy_from_slice(&self.chunk_index.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_buf);

        let plaintext = cipher
            .decrypt(nonce, ct_buf.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("AES-GCM: {e}")))?;

        self.buffer = plaintext;
        self.buf_pos = 0;
        self.chunk_index += 1;
        Ok(true)
    }
}

impl<R: Read> Read for ChunkDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // Serve from current buffer
            if self.buf_pos < self.buffer.len() {
                let avail = self.buffer.len() - self.buf_pos;
                let n = avail.min(buf.len());
                buf[..n].copy_from_slice(&self.buffer[self.buf_pos..self.buf_pos + n]);
                self.buf_pos += n;
                return Ok(n);
            }

            if self.done {
                return Ok(0);
            }

            // Load next chunk
            if !self.load_next_chunk()? {
                return Ok(0);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

unsafe fn serialize_element(out: &mut Vec<u8>, elem: *mut pbc_bkem_sys::element_s) {
    let len = pbc_bkem_sys::himitsu_element_length_in_bytes(elem) as usize;
    out.extend_from_slice(&(len as u32).to_le_bytes());
    let start = out.len();
    out.resize(start + len, 0);
    pbc_bkem_sys::himitsu_element_to_bytes(out[start..].as_mut_ptr(), elem);
}

unsafe fn deserialize_element(
    elem: *mut pbc_bkem_sys::element_s,
    data: &[u8],
    cursor: &mut usize,
) {
    let len = read_u32(data, cursor) as usize;
    pbc_bkem_sys::himitsu_element_from_bytes(elem, data[*cursor..].as_ptr() as *mut _);
    *cursor += len;
}

fn read_u32(data: &[u8], cursor: &mut usize) -> u32 {
    let val = u32::from_le_bytes(data[*cursor..*cursor + 4].try_into().unwrap());
    *cursor += 4;
    val
}
