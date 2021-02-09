

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use ed25519_dalek::Keypair;
    use ed25519_dalek::Signature;
    use ed25519_dalek::{Signer, PublicKey, Verifier};

    #[test]
    fn test_signature() {
        let mut csprng = OsRng;
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let message: &[u8] = b"This is a test of the tsunami alert system.";
        let signature: Signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());

        let public_key: PublicKey = keypair.public;
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_signature_serde() {
        use bincode;
        
        let mut csprng = OsRng;
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let message: &[u8] = b"This is a test of the tsunami alert system.";
        let signature: Signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());

        let public_key: PublicKey = keypair.public;
        assert!(public_key.verify(message, &signature).is_ok());

        let message_b = bincode::serialize(message).unwrap();
        let signature_b = bincode::serialize(&signature).unwrap();
        let pk_b = bincode::serialize(&public_key).unwrap();

        let message_d: &[u8] = bincode::deserialize(&message_b).unwrap();
        let pk_d: PublicKey = bincode::deserialize(&pk_b).unwrap();
        let signature_d: Signature = bincode::deserialize(&signature_b).unwrap();

        assert!(pk_d.verify(message_d, &signature_d).is_ok());
    }
}