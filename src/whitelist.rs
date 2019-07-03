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
    whitelist: BTreeSet<Vec<u8>>,
}

impl Whitelist {
    pub fn new<'a>(elems: impl IntoIterator<Item = &'a [u8; 65]>) -> Self {
        Whitelist {
            whitelist: elems.into_iter().map(|a| a.to_vec()).collect(),
        }
    }

    fn matches(&self, presented_certs: &[Certificate]) -> Result<(), TLSError> {
        // One cert was presented
        let presented_cert = match &presented_certs {
            [presented_cert] => Ok(presented_cert),
            _ => Err(TLSError::WebPKIError(
                webpki::Error::PathLenConstraintViolated,
            )),
        }?;

        // cert is valid x509 der
        let parsed = x509_parser::parse_x509_der(presented_cert.as_ref())
            .map_err(|_| TLSError::WebPKIError(webpki::Error::BadDER))
            .and_then(|(rest, parsed)| {
                // make sure there is no more data tobe parsed
                if rest.len() == 0 {
                    Ok(parsed)
                } else {
                    Err(TLSError::WebPKIError(webpki::Error::BadDER))
                }
            })?;

        if self.whitelist.contains(
            parsed
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .as_ref(),
        ) {
            Ok(())
        } else {
            dbg!(parsed
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .as_ref()
                .len());
            dbg!(
                parsed
                    .tbs_certificate
                    .subject_pki
                    .subject_public_key
                    .as_ref()[0]
            );
            Err(TLSError::WebPKIError(webpki::Error::UnknownIssuer))
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
        self.matches(presented_certs)
            .map(|()| ServerCertVerified::assertion())
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
        self.matches(presented_certs)
            .map(|()| ClientCertVerified::assertion())
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

// AlgorithmIdentifier {
//     algorithm: OID(1.2.840.10045.2.1),
//     parameters: DerObject {
//         class: 0,
//         structured: 0,
//         tag: 255,
//         content: ContextSpecific(
//             0,
//             Some(
//                 DerObject {
//                     class: 0,
//                     structured: 0,
//                     tag: 6,
//                     content: OID(
//                         OID(1.2.840.10045.3.1.7),
//                     ),
//                 },
//             ),
//         ),
//     },
// }
