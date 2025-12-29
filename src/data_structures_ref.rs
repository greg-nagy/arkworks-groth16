//! Zero-copy data structures for Groth16.
//!
//! This module provides `ProvingKeyRef`, a borrowed version of `ProvingKey` that uses
//! slices instead of `Vec`s. This enables zero-copy deserialization from embedded
//! binary data, eliminating the ~2s deserialization overhead on mobile devices.
//!
//! # Usage
//!
//! ```ignore
//! // From an existing ProvingKey (for testing/migration)
//! let pk: ProvingKey<Bn254> = ...;
//! let pk_ref = ProvingKeyRef::from(&pk);
//!
//! // From embedded binary data (zero-copy, production use)
//! static PK_DATA: &[u8] = include_bytes!("../keys/pk.bin");
//! let pk_ref = ProvingKeyRef::<Bn254>::from_bytes_unchecked(PK_DATA)?;
//! ```

use ark_ec::pairing::Pairing;

use crate::{ProvingKey, VerifyingKey};

/// A borrowed proving key for Groth16 that references data without owning it.
///
/// This is the zero-copy counterpart to [`ProvingKey`]. All vector fields are
/// replaced with slices, allowing the key to reference static or embedded data
/// directly without allocation or deserialization.
///
/// # Lifetime
///
/// The lifetime `'a` represents the lifetime of the underlying data. For embedded
/// keys, this will typically be `'static`.
///
/// # Example
///
/// ```ignore
/// // Create from an existing ProvingKey
/// let pk: ProvingKey<Bn254> = generate_keys(&circuit)?;
/// let pk_ref: ProvingKeyRef<Bn254> = ProvingKeyRef::from(&pk);
///
/// // Use for proving (same API as ProvingKey)
/// let proof = Groth16::prove_with_ref(&pk_ref, circuit, &mut rng)?;
/// ```
#[derive(Clone, Debug)]
pub struct ProvingKeyRef<'a, E: Pairing> {
    /// The underlying verification key (owned, since it's small).
    pub vk: VerifyingKey<E>,
    /// The element `beta * G` in `E::G1`.
    pub beta_g1: E::G1Affine,
    /// The element `delta * G` in `E::G1`.
    pub delta_g1: E::G1Affine,
    /// The elements `a_i * G` in `E::G1`.
    pub a_query: &'a [E::G1Affine],
    /// The elements `b_i * G` in `E::G1`.
    pub b_g1_query: &'a [E::G1Affine],
    /// The elements `b_i * H` in `E::G2`.
    pub b_g2_query: &'a [E::G2Affine],
    /// The elements `h_i * G` in `E::G1`.
    pub h_query: &'a [E::G1Affine],
    /// The elements `l_i * G` in `E::G1`.
    pub l_query: &'a [E::G1Affine],
}

impl<'a, E: Pairing> From<&'a ProvingKey<E>> for ProvingKeyRef<'a, E> {
    /// Creates a `ProvingKeyRef` that borrows from an existing `ProvingKey`.
    ///
    /// This is useful for:
    /// - Testing the zero-copy code path with existing keys
    /// - Gradual migration from owned to borrowed keys
    /// - Situations where you have a `ProvingKey` but need the `Ref` API
    fn from(pk: &'a ProvingKey<E>) -> Self {
        Self {
            vk: pk.vk.clone(),
            beta_g1: pk.beta_g1,
            delta_g1: pk.delta_g1,
            a_query: &pk.a_query,
            b_g1_query: &pk.b_g1_query,
            b_g2_query: &pk.b_g2_query,
            h_query: &pk.h_query,
            l_query: &pk.l_query,
        }
    }
}

impl<'a, E: Pairing> ProvingKeyRef<'a, E> {
    /// Returns the number of constraints in the circuit.
    ///
    /// This is derived from the h_query length, which equals
    /// `domain_size - 1` where `domain_size >= num_constraints`.
    pub fn num_constraints_hint(&self) -> usize {
        self.h_query.len()
    }

    /// Returns the number of instance (public input) variables.
    pub fn num_instance_variables(&self) -> usize {
        self.vk.gamma_abc_g1.len()
    }

    /// Returns the number of witness (private input) variables.
    ///
    /// This equals `a_query.len() - num_instance_variables`.
    pub fn num_witness_variables(&self) -> usize {
        self.a_query.len().saturating_sub(self.num_instance_variables())
    }
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

    /// Simple test circuit: a * b = c
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
    fn test_proving_key_ref_from_proving_key() {
        use crate::Groth16;
        use ark_crypto_primitives::snark::SNARK;

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        // Generate a proving key
        let circuit = TestCircuit::<ark_bn254::Fr> { a: None, b: None };
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng).unwrap();

        // Convert to ProvingKeyRef
        let pk_ref = ProvingKeyRef::from(&pk);

        // Verify all fields match
        assert_eq!(pk_ref.vk.alpha_g1, pk.vk.alpha_g1);
        assert_eq!(pk_ref.vk.beta_g2, pk.vk.beta_g2);
        assert_eq!(pk_ref.vk.gamma_g2, pk.vk.gamma_g2);
        assert_eq!(pk_ref.vk.delta_g2, pk.vk.delta_g2);
        assert_eq!(pk_ref.vk.gamma_abc_g1.len(), pk.vk.gamma_abc_g1.len());
        for (a, b) in pk_ref.vk.gamma_abc_g1.iter().zip(pk.vk.gamma_abc_g1.iter()) {
            assert_eq!(a, b);
        }
        assert_eq!(pk_ref.beta_g1, pk.beta_g1);
        assert_eq!(pk_ref.delta_g1, pk.delta_g1);

        // Verify slice contents match vec contents
        assert_eq!(pk_ref.a_query.len(), pk.a_query.len());
        assert_eq!(pk_ref.b_g1_query.len(), pk.b_g1_query.len());
        assert_eq!(pk_ref.b_g2_query.len(), pk.b_g2_query.len());
        assert_eq!(pk_ref.h_query.len(), pk.h_query.len());
        assert_eq!(pk_ref.l_query.len(), pk.l_query.len());

        for (a, b) in pk_ref.a_query.iter().zip(pk.a_query.iter()) {
            assert_eq!(a, b);
        }
        for (a, b) in pk_ref.b_g1_query.iter().zip(pk.b_g1_query.iter()) {
            assert_eq!(a, b);
        }
        for (a, b) in pk_ref.b_g2_query.iter().zip(pk.b_g2_query.iter()) {
            assert_eq!(a, b);
        }
        for (a, b) in pk_ref.h_query.iter().zip(pk.h_query.iter()) {
            assert_eq!(a, b);
        }
        for (a, b) in pk_ref.l_query.iter().zip(pk.l_query.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_proving_key_ref_metadata() {
        use crate::Groth16;
        use ark_crypto_primitives::snark::SNARK;

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let circuit = TestCircuit::<ark_bn254::Fr> { a: None, b: None };
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng).unwrap();
        let pk_ref = ProvingKeyRef::from(&pk);

        // Our test circuit has 1 public input (c) plus the constant 1
        assert_eq!(pk_ref.num_instance_variables(), 2);

        // Witness variables: a, b
        assert_eq!(pk_ref.num_witness_variables(), pk.a_query.len() - 2);

        // h_query length should be positive
        assert!(pk_ref.num_constraints_hint() > 0);
    }
}

