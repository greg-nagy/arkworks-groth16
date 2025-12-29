//! Zero-copy binary format for proving keys.
//!
//! This module provides a binary serialization format optimized for zero-copy
//! loading of proving keys. The format stores curve points in uncompressed form
//! with explicit layout, enabling direct memory mapping without deserialization.
//!
//! # Format Overview
//!
//! ```text
//! [Header: 64 bytes]
//!   - Magic: 4 bytes ("ZPK1")
//!   - Version: 4 bytes (little-endian u32)
//!   - Flags: 4 bytes (reserved)
//!   - Point size G1: 4 bytes (size of G1Affine in bytes)
//!   - Point size G2: 4 bytes (size of G2Affine in bytes)
//!   - VK length: 8 bytes (serialized VK size)
//!   - a_query length: 8 bytes (number of points)
//!   - b_g1_query length: 8 bytes
//!   - b_g2_query length: 8 bytes
//!   - h_query length: 8 bytes
//!   - l_query length: 8 bytes
//!
//! [Checksum: 32 bytes] (SHA-256 of everything after checksum)
//!
//! [VK: variable] (arkworks compressed serialization)
//!
//! [beta_g1: G1 point size]
//! [delta_g1: G1 point size]
//!
//! [a_query: a_len × G1 point size]
//! [b_g1_query: b_g1_len × G1 point size]
//! [b_g2_query: b_g2_len × G2 point size]
//! [h_query: h_len × G1 point size]
//! [l_query: l_len × G1 point size]
//! ```

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::vec::Vec;
use sha2::{Digest, Sha256};

use crate::{ProvingKey, VerifyingKey};

/// Magic bytes identifying a zero-copy proving key file.
pub const MAGIC: &[u8; 4] = b"ZPK1";

/// Current format version.
pub const VERSION: u32 = 1;

/// Header size in bytes (68 bytes + 4 padding for alignment).
pub const HEADER_SIZE: usize = 72;

/// Checksum size in bytes.
pub const CHECKSUM_SIZE: usize = 32;

/// Error type for zero-copy operations.
#[derive(Debug)]
pub enum ZeroCopyError {
    /// Invalid magic bytes.
    InvalidMagic,
    /// Unsupported format version.
    UnsupportedVersion(u32),
    /// Data is too short.
    DataTooShort {
        /// Expected number of bytes.
        expected: usize,
        /// Actual number of bytes.
        actual: usize,
    },
    /// Checksum mismatch.
    ChecksumMismatch,
    /// Point size mismatch (binary was created for different curve).
    PointSizeMismatch {
        /// Expected G1 point size.
        expected_g1: usize,
        /// Actual G1 point size in file.
        actual_g1: usize,
    },
    /// Serialization error.
    SerializationError(String),
    /// Alignment error.
    AlignmentError {
        /// Memory address that was misaligned.
        address: usize,
        /// Required alignment.
        required: usize,
    },
}

impl core::fmt::Display for ZeroCopyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid magic bytes"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version: {}", v),
            Self::DataTooShort { expected, actual } => {
                write!(f, "data too short: expected {} bytes, got {}", expected, actual)
            }
            Self::ChecksumMismatch => write!(f, "checksum mismatch"),
            Self::PointSizeMismatch { expected_g1, actual_g1 } => {
                write!(f, "point size mismatch: expected G1={}, got G1={}", expected_g1, actual_g1)
            }
            Self::SerializationError(msg) => write!(f, "serialization error: {}", msg),
            Self::AlignmentError { address, required } => {
                write!(f, "alignment error: address {} not aligned to {}", address, required)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ZeroCopyError {}

/// Header structure for the zero-copy format.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Header {
    /// Magic bytes.
    pub magic: [u8; 4],
    /// Format version.
    pub version: u32,
    /// Flags (reserved for future use).
    pub flags: u32,
    /// Size of G1Affine in bytes.
    pub g1_point_size: u32,
    /// Size of G2Affine in bytes.
    pub g2_point_size: u32,
    /// Padding for 8-byte alignment.
    pub _padding: u32,
    /// Length of serialized VerifyingKey.
    pub vk_len: u64,
    /// Number of points in a_query.
    pub a_query_len: u64,
    /// Number of points in b_g1_query.
    pub b_g1_query_len: u64,
    /// Number of points in b_g2_query.
    pub b_g2_query_len: u64,
    /// Number of points in h_query.
    pub h_query_len: u64,
    /// Number of points in l_query.
    pub l_query_len: u64,
}

impl Header {
    /// Serialize header to bytes.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        let mut offset = 0;

        bytes[offset..offset + 4].copy_from_slice(&self.magic);
        offset += 4;

        bytes[offset..offset + 4].copy_from_slice(&self.version.to_le_bytes());
        offset += 4;

        bytes[offset..offset + 4].copy_from_slice(&self.flags.to_le_bytes());
        offset += 4;

        bytes[offset..offset + 4].copy_from_slice(&self.g1_point_size.to_le_bytes());
        offset += 4;

        bytes[offset..offset + 4].copy_from_slice(&self.g2_point_size.to_le_bytes());
        offset += 4;

        // Padding
        bytes[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());
        offset += 4;

        bytes[offset..offset + 8].copy_from_slice(&self.vk_len.to_le_bytes());
        offset += 8;

        bytes[offset..offset + 8].copy_from_slice(&self.a_query_len.to_le_bytes());
        offset += 8;

        bytes[offset..offset + 8].copy_from_slice(&self.b_g1_query_len.to_le_bytes());
        offset += 8;

        bytes[offset..offset + 8].copy_from_slice(&self.b_g2_query_len.to_le_bytes());
        offset += 8;

        bytes[offset..offset + 8].copy_from_slice(&self.h_query_len.to_le_bytes());
        offset += 8;

        bytes[offset..offset + 8].copy_from_slice(&self.l_query_len.to_le_bytes());

        bytes
    }

    /// Parse header from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZeroCopyError> {
        if bytes.len() < HEADER_SIZE {
            return Err(ZeroCopyError::DataTooShort {
                expected: HEADER_SIZE,
                actual: bytes.len(),
            });
        }

        let mut offset = 0;

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[offset..offset + 4]);
        offset += 4;

        if &magic != MAGIC {
            return Err(ZeroCopyError::InvalidMagic);
        }

        let version = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        if version != VERSION {
            return Err(ZeroCopyError::UnsupportedVersion(version));
        }

        let flags = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let g1_point_size = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let g2_point_size = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // Skip padding
        let _padding = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let vk_len = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let a_query_len = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let b_g1_query_len = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let b_g2_query_len = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let h_query_len = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let l_query_len = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());

        Ok(Self {
            magic,
            version,
            flags,
            g1_point_size,
            g2_point_size,
            _padding: 0,
            vk_len,
            a_query_len,
            b_g1_query_len,
            b_g2_query_len,
            h_query_len,
            l_query_len,
        })
    }

    /// Calculate total expected size of the data section.
    pub fn data_size(&self) -> usize {
        let g1_size = self.g1_point_size as usize;
        let g2_size = self.g2_point_size as usize;

        self.vk_len as usize
            + 2 * g1_size // beta_g1, delta_g1
            + self.a_query_len as usize * g1_size
            + self.b_g1_query_len as usize * g1_size
            + self.b_g2_query_len as usize * g2_size
            + self.h_query_len as usize * g1_size
            + self.l_query_len as usize * g1_size
    }

    /// Calculate total expected file size.
    pub fn total_size(&self) -> usize {
        HEADER_SIZE + CHECKSUM_SIZE + self.data_size()
    }
}

/// Serialize a proving key to zero-copy format.
///
/// The output can be embedded in a binary and loaded with `ProvingKeyRef::from_bytes_unchecked`.
pub fn serialize<E: Pairing>(pk: &ProvingKey<E>) -> Result<Vec<u8>, ZeroCopyError> {
    // Get serialized point sizes (uncompressed)
    let g1_size = pk.beta_g1.serialized_size(Compress::No);
    let g2_size = pk.vk.beta_g2.serialized_size(Compress::No);

    // Serialize VK
    let mut vk_bytes = Vec::new();
    pk.vk
        .serialize_with_mode(&mut vk_bytes, Compress::Yes)
        .map_err(|e| ZeroCopyError::SerializationError(e.to_string()))?;

    // Build header
    let header = Header {
        magic: *MAGIC,
        version: VERSION,
        flags: 0,
        g1_point_size: g1_size as u32,
        g2_point_size: g2_size as u32,
        _padding: 0,
        vk_len: vk_bytes.len() as u64,
        a_query_len: pk.a_query.len() as u64,
        b_g1_query_len: pk.b_g1_query.len() as u64,
        b_g2_query_len: pk.b_g2_query.len() as u64,
        h_query_len: pk.h_query.len() as u64,
        l_query_len: pk.l_query.len() as u64,
    };

    // Allocate output buffer
    let total_size = header.total_size();
    let mut output = Vec::with_capacity(total_size);

    // Write header
    output.extend_from_slice(&header.to_bytes());

    // Reserve space for checksum (will fill later)
    let checksum_start = output.len();
    output.extend_from_slice(&[0u8; CHECKSUM_SIZE]);

    // Write VK
    output.extend_from_slice(&vk_bytes);

    // Write beta_g1, delta_g1
    serialize_g1_point::<E>(&mut output, &pk.beta_g1)?;
    serialize_g1_point::<E>(&mut output, &pk.delta_g1)?;

    // Write query arrays
    for point in &pk.a_query {
        serialize_g1_point::<E>(&mut output, point)?;
    }
    for point in &pk.b_g1_query {
        serialize_g1_point::<E>(&mut output, point)?;
    }
    for point in &pk.b_g2_query {
        serialize_g2_point::<E>(&mut output, point)?;
    }
    for point in &pk.h_query {
        serialize_g1_point::<E>(&mut output, point)?;
    }
    for point in &pk.l_query {
        serialize_g1_point::<E>(&mut output, point)?;
    }

    // Compute checksum over data (everything after the checksum field)
    let checksum = compute_checksum(&output[HEADER_SIZE + CHECKSUM_SIZE..]);
    output[checksum_start..checksum_start + CHECKSUM_SIZE].copy_from_slice(&checksum);

    debug_assert_eq!(output.len(), total_size);

    Ok(output)
}

/// Deserialize verifying key from the zero-copy format.
///
/// This is a helper used during `ProvingKeyRef::from_bytes_unchecked`.
pub fn deserialize_vk<E: Pairing>(data: &[u8]) -> Result<VerifyingKey<E>, ZeroCopyError> {
    VerifyingKey::deserialize_with_mode(data, Compress::Yes, Validate::No)
        .map_err(|e| ZeroCopyError::SerializationError(e.to_string()))
}

/// Serialize a G1 affine point using its raw memory representation.
fn serialize_g1_point<E: Pairing>(output: &mut Vec<u8>, point: &E::G1Affine) -> Result<(), ZeroCopyError> {
    // Use uncompressed serialization for predictable size
    point
        .serialize_with_mode(output, Compress::No)
        .map_err(|e| ZeroCopyError::SerializationError(e.to_string()))
}

/// Serialize a G2 affine point using its raw memory representation.
fn serialize_g2_point<E: Pairing>(output: &mut Vec<u8>, point: &E::G2Affine) -> Result<(), ZeroCopyError> {
    point
        .serialize_with_mode(output, Compress::No)
        .map_err(|e| ZeroCopyError::SerializationError(e.to_string()))
}

/// Compute SHA-256 checksum of data.
fn compute_checksum(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Verify the checksum of zero-copy data.
pub fn verify_checksum(data: &[u8]) -> Result<(), ZeroCopyError> {
    if data.len() < HEADER_SIZE + CHECKSUM_SIZE {
        return Err(ZeroCopyError::DataTooShort {
            expected: HEADER_SIZE + CHECKSUM_SIZE,
            actual: data.len(),
        });
    }

    let stored_checksum = &data[HEADER_SIZE..HEADER_SIZE + CHECKSUM_SIZE];
    let computed_checksum = compute_checksum(&data[HEADER_SIZE + CHECKSUM_SIZE..]);

    if stored_checksum != computed_checksum {
        return Err(ZeroCopyError::ChecksumMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_ff::Field;
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_std::{rand::{RngCore, SeedableRng}, test_rng};

    /// Simple test circuit.
    struct TestCircuit<F: Field> {
        a: Option<F>,
        b: Option<F>,
    }

    impl<F: Field> ConstraintSynthesizer<F> for TestCircuit<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.new_input_variable(|| {
                let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(a * b)
            })?;
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            Ok(())
        }
    }

    #[test]
    fn test_header_roundtrip() {
        let header = Header {
            magic: *MAGIC,
            version: VERSION,
            flags: 0,
            g1_point_size: 64,
            g2_point_size: 128,
            _padding: 0,
            vk_len: 1234,
            a_query_len: 100,
            b_g1_query_len: 100,
            b_g2_query_len: 100,
            h_query_len: 50,
            l_query_len: 50,
        };

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);

        let parsed = Header::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.magic, header.magic);
        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.g1_point_size, header.g1_point_size);
        assert_eq!(parsed.g2_point_size, header.g2_point_size);
        assert_eq!(parsed.vk_len, header.vk_len);
        assert_eq!(parsed.a_query_len, header.a_query_len);
        assert_eq!(parsed.b_g1_query_len, header.b_g1_query_len);
        assert_eq!(parsed.b_g2_query_len, header.b_g2_query_len);
        assert_eq!(parsed.h_query_len, header.h_query_len);
        assert_eq!(parsed.l_query_len, header.l_query_len);
    }

    #[test]
    fn test_serialize_proving_key() {
        use crate::Groth16;
        use ark_crypto_primitives::snark::SNARK;

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        // Generate a proving key
        let circuit = TestCircuit::<ark_bn254::Fr> { a: None, b: None };
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng).unwrap();

        // Serialize to zero-copy format
        let data = serialize(&pk).unwrap();

        // Parse header
        let header = Header::from_bytes(&data).unwrap();
        assert_eq!(header.magic, *MAGIC);
        assert_eq!(header.version, VERSION);
        assert_eq!(header.a_query_len as usize, pk.a_query.len());
        assert_eq!(header.b_g1_query_len as usize, pk.b_g1_query.len());
        assert_eq!(header.b_g2_query_len as usize, pk.b_g2_query.len());
        assert_eq!(header.h_query_len as usize, pk.h_query.len());
        assert_eq!(header.l_query_len as usize, pk.l_query.len());

        // Verify checksum
        verify_checksum(&data).unwrap();

        // Verify total size matches
        assert_eq!(data.len(), header.total_size());
    }

    #[test]
    fn test_checksum_detects_corruption() {
        use crate::Groth16;
        use ark_crypto_primitives::snark::SNARK;

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let circuit = TestCircuit::<ark_bn254::Fr> { a: None, b: None };
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng).unwrap();

        let mut data = serialize(&pk).unwrap();

        // Corrupt a byte in the data section
        let corrupt_idx = HEADER_SIZE + CHECKSUM_SIZE + 10;
        data[corrupt_idx] ^= 0xFF;

        // Checksum should fail
        assert!(matches!(
            verify_checksum(&data),
            Err(ZeroCopyError::ChecksumMismatch)
        ));
    }
}

