use rcgen::KeyPair;
use rcgen::RcgenError;

pub trait KeyPairExt {
    /// Generate keypair using project default settings
    fn gen() -> KeyPair;

    /// Generate a self signed certificate
    fn sign_self(&self) -> Result<rustls::Certificate, RcgenError>;

    /// extract the secret key from a rcgen KeyPair
    fn as_rustls_sk(&self) -> rustls::PrivateKey;

    /// Keypair lacks a Clone implementation
    /// This function makes a copy by serializing then deserializing
    fn clone_self(&self) -> KeyPair;

    /// Get public key from keypair
    fn get_pub(&self) -> ();
}

impl KeyPairExt for KeyPair {
    fn gen() -> KeyPair {
        KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap()
    }

    fn sign_self(&self) -> Result<rustls::Certificate, RcgenError> {
        let keypair = self.clone_self();
        let mut cert_params = rcgen::CertificateParams::default();
        cert_params.key_pair = Some(keypair);
        let rc_cert = rcgen::Certificate::from_params(cert_params)?;
        Ok(rustls::Certificate(rc_cert.serialize_der()?))
    }

    fn as_rustls_sk(&self) -> rustls::PrivateKey {
        rustls::PrivateKey(self.serialize_der())
    }

    fn clone_self(&self) -> KeyPair {
        let pem = self.serialize_pem();
        KeyPair::from_pem(&pem).unwrap()
    }

    fn get_pub(&self) -> () {
        unimplemented!()
    }
}
