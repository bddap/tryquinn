use rustls::Certificate;
use rustls::ClientCertVerified;
use rustls::ClientCertVerifier;
use rustls::DistinguishedNames;
use rustls::RootCertStore;
use rustls::ServerCertVerified;
use rustls::ServerCertVerifier;
use rustls::TLSError;
use std::collections::BTreeSet;
use webpki::DNSNameRef;

pub struct Whitelist {
    whitelist: BTreeSet<[u8; 32]>,
}

impl Whitelist {
    pub fn new<'a>(elems: impl IntoIterator<Item = &'a [u8; 32]>) -> Self {
        Whitelist {
            whitelist: elems.into_iter().map(Clone::clone).collect(),
        }
    }

    fn matches(&self, presented_certs: &[Certificate]) -> bool {
        // Assert that signee is in the whitelist
        // Assert the signee == the signer
        dbg!(presented_certs);
        dbg!(&self.whitelist);
        if let [_presented_cert] = &presented_certs {
            unimplemented!()
        } else {
            false
        }
    }
}

impl ServerCertVerifier for Whitelist {
    fn verify_server_cert(
        &self,
        _roots: &RootCertStore,
        presented_certs: &[Certificate],
        _dns_name: DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        if self.matches(presented_certs) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TLSError::WebPKIError(
                webpki::Error::PathLenConstraintViolated,
            ))
        }
    }
}

impl ClientCertVerifier for Whitelist {
    fn client_auth_root_subjects(&self) -> DistinguishedNames {
        DistinguishedNames::new() // TODO: Review
    }

    fn verify_client_cert(
        &self,
        presented_certs: &[Certificate],
    ) -> Result<ClientCertVerified, TLSError> {
        if self.matches(presented_certs) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(TLSError::WebPKIError(
                webpki::Error::PathLenConstraintViolated,
            ))
        }
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}
