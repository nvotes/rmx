

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use ed25519_dalek::Keypair;
    use ed25519_dalek::Signature;
    use ed25519_dalek::{Signer, PublicKey, Verifier};

    use crate::data::bytes::{Ser, Deser};

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
        let mut csprng = OsRng;
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let message: &[u8] = b"This is a test of the tsunami alert system.";
        let signature: Signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());

        let public_key: PublicKey = keypair.public;
        assert!(public_key.verify(message, &signature).is_ok());

        let message_b = message.to_vec().ser();
        let signature_b = signature.ser();
        let pk_b = public_key.ser();
        
        let message_d = Vec::<u8>::deser(&message_b).unwrap();
        let pk_d = PublicKey::deser(&pk_b).unwrap();
        let signature_d = Signature::deser(&signature_b).unwrap();
        
        assert!(pk_d.verify(&message_d, &signature_d).is_ok());
    }
}