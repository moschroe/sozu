use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use std::io::BufReader;
use rustls::{ClientHello};
use webpki;
use rustls::{ResolvesServerCert, SignatureScheme, RootCertStore, ClientCertVerifier, ClientCertVerified, DistinguishedNames, TLSError, Certificate, AllowAnyAuthenticatedClient};
use rustls::sign::{CertifiedKey, RSASigningKey};
use rustls::internal::pemfile;

use sozu_command::proxy::{CertificateAndKey, CertificateFingerprint, AddCertificate, RemoveCertificate, AddClientCa, RemoveClientCa};
use sozu_command::certificate::calculate_fingerprint_from_der;

use router::trie::TrieNode;

struct TlsData {
  pub cert:     CertifiedKey,
}

pub struct CertificateResolver {
  pub domains:  TrieNode<CertificateFingerprint>,
  certificates: HashMap<CertificateFingerprint, TlsData>,
}

impl CertificateResolver {
  pub fn new() -> CertificateResolver {
    CertificateResolver {
      domains:      TrieNode::root(),
      certificates: HashMap::new(),
    }
  }

  pub fn add_certificate(&mut self, add_certificate: AddCertificate) -> Option<CertificateFingerprint> {
    if let Some(certified_key) = generate_certified_key(add_certificate.certificate) {
      let fingerprint = calculate_fingerprint_from_der(&certified_key.cert[0].0);
      if add_certificate.names.is_empty() {
        //FIXME: waiting for https://github.com/briansmith/webpki/pull/65 to merge to get the DNS names
        // create a untrusted::Input
        // let input = untrusted::Input::from(&certs[0].0);
        // create an EndEntityCert
        // let ee = webpki::EndEntityCert::from(input).unwrap()
        // get names
        // let dns_names = ee.list_dns_names()
        // names.extend(dns_names.drain(..).map(|name| name.to_String()));
        error!("the rustls proxy cannot extract the names from the certificate (fingerprint={:?})", fingerprint);
        return None;
      }

      let mut names = add_certificate.names;
      //info!("cert fingerprint: {:?}", fingerprint);

      let data = TlsData {
        cert:     certified_key,
      };

      let fingerprint = CertificateFingerprint(fingerprint);
      self.certificates.insert(fingerprint.clone(), data);
      for name in names.drain(..) {
        self.domains.domain_insert(name.into_bytes(), fingerprint.clone());
      }

      Some(fingerprint)
    } else {
      None
    }
  }

  pub fn remove_certificate(&mut self, remove_certificate: RemoveCertificate) {
    if let Some(_data) = self.certificates.get(&remove_certificate.fingerprint) {
      //let cert = &data.cert.cert[0];
      if remove_certificate.names.is_empty() {
        //FIXME: waiting for https://github.com/briansmith/webpki/pull/65 to merge to get the DNS names
        // create a untrusted::Input
        // let input = untrusted::Input::from(&certs[0].0);
        // create an EndEntityCert
        // let ee = webpki::EndEntityCert::from(input).unwrap()
        // get names
        // let dns_names = ee.list_dns_names()
        // names.extend(dns_names.drain(..).map(|name| name.to_String()));
        unimplemented!("the rustls proxy cannot extract the names from the certificate");
      }

      let names = remove_certificate.names;

      for name in names {
        self.domains.domain_remove(&name.into_bytes());
      }
    }

    self.certificates.remove(&remove_certificate.fingerprint);
  }
}

pub struct CertificateResolverWrapper(pub Mutex<CertificateResolver>);

impl CertificateResolverWrapper {
  pub fn new() -> CertificateResolverWrapper {
    CertificateResolverWrapper(Mutex::new(CertificateResolver::new()))
  }

  pub fn add_certificate(&self, add_certificate: AddCertificate) -> Option<CertificateFingerprint> {
    if let Ok(ref mut resolver) = self.0.try_lock() {
      resolver.add_certificate(add_certificate)
    } else {
      None
    }
  }

  pub fn remove_certificate(&self, remove_certificate: RemoveCertificate) {
    if let Ok(ref mut resolver) = self.0.try_lock() {
      resolver.remove_certificate(remove_certificate)
    }

  }
}

impl ResolvesServerCert for CertificateResolverWrapper {
  fn resolve(
        &self,
        client_hello: ClientHello,
    ) -> Option<CertifiedKey> {
    let server_name = client_hello.server_name();
    let sigschemes = client_hello.sigschemes();

    if server_name.is_none() {
      error!("cannot look up certificate: no SNI from session");
      return None;
    }
    let name: &str = server_name.unwrap().into();

    trace!("trying to resolve name: {:?} for signature scheme: {:?}", name, sigschemes);
    if let Ok(ref mut resolver) = self.0.try_lock() {
      //resolver.domains.print();
      if let Some(kv) = resolver.domains.domain_lookup(name.as_bytes(), true) {
         trace!("looking for certificate for {:?} with fingerprint {:?}", name, kv.1);
         return resolver.certificates.get(&kv.1).as_ref().map(|data| data.cert.clone());
      }
    }

    error!("could not look up a certificate for server name '{}'", name);
    None
  }
}

pub struct DynamicClientCertificateVerifier {
  roots: HashMap<CertFingerprint, rustls::Certificate>,
  inner: Arc<(dyn ClientCertVerifier + 'static)>,
}

impl DynamicClientCertificateVerifier {
  pub fn new() -> Self {
    let roots = RootCertStore::empty();
    DynamicClientCertificateVerifier {
      roots: HashMap::new(),
      inner: AllowAnyAuthenticatedClient::new(roots),
    }
  }

  pub fn add_ca_cert(&mut self, add: AddClientCa) -> Option<CertFingerprint> {
    // self.roots.
    let mut rdr_cert = BufReader::new(add.certificate.as_bytes());
    let mut certs = match pemfile::certs(&mut rdr_cert) {
      Ok(cert) => cert,
      Err(err) => {
        error!("unable to parse client ca cert: {:?}", err);
        return None;
      }
    };
    let cert;
    if let Some(first_cert) = certs.pop() {
      cert = first_cert;
    } else {
      error!("unable to parse exactly one cert from provided client CA data, got {}", certs.len());
      return None;
    };
    if certs.len() > 0 {
      error!("unable to parse exactly one cert from provided client CA data, got {}", certs.len() + 1);
      return None;
    }
    std::mem::drop(certs);
    let mut new_roots = RootCertStore::empty();
    if let Err(err) = new_roots.add(&cert) {
      error!("unable to add new client CA to RootCertStore: {}", err);
      return None;
    };
    for cert in self.roots.values() {
      if let Err(err) = new_roots.add(cert) {
        error!("unable to add existing client CA to RootCertStore: {}", err);
        return None;
      };
    }
    let fp = CertFingerprint(calculate_fingerprint_from_der(&cert.0));
    self.roots.insert(fp.clone(), cert);
    // make new verifier
    self.inner = AllowAnyAuthenticatedClient::new(new_roots);
    Some(fp)
  }
}

impl ClientCertVerifier for DynamicClientCertificateVerifier {
  fn client_auth_root_subjects(&self) -> DistinguishedNames {
    self.inner.client_auth_root_subjects()
  }

  fn verify_client_cert(&self, presented_certs: &[Certificate]) -> Result<ClientCertVerified, TLSError> {
    self.inner.verify_client_cert(presented_certs)
  }
}

pub struct ClientCertificateVerifierWrapper(pub RwLock<CertificateResolver>);

pub fn generate_certified_key(certificate_and_key: CertificateAndKey) -> Option<CertifiedKey> {
  let mut chain = Vec::new();

  let mut cert_reader = BufReader::new(certificate_and_key.certificate.as_bytes());
  let parsed_certs = pemfile::certs(&mut cert_reader);

  if let Ok(certs) = parsed_certs {
    for cert in certs {
      chain.push(cert);
    }
  } else {
    return None;
  }

  for ref cert in certificate_and_key.certificate_chain.iter() {
    let mut chain_cert_reader = BufReader::new(cert.as_bytes());
    if let Ok(parsed_chain_certs) = pemfile::certs(&mut chain_cert_reader) {
      for cert in parsed_chain_certs {
        chain.push(cert);
      }
    }
  }

  let mut key_reader = BufReader::new(certificate_and_key.key.as_bytes());
  let parsed_key = pemfile::rsa_private_keys(&mut key_reader);

  if let Ok(keys) = parsed_key {
    if !keys.is_empty() {
      if let Ok(signing_key) = RSASigningKey::new(&keys[0]) {
        let certified = CertifiedKey::new(chain, Arc::new(Box::new(signing_key)));
        return Some(certified);
      }
    } else {
      let mut key_reader = BufReader::new(certificate_and_key.key.as_bytes());
      let parsed_key = pemfile::pkcs8_private_keys(&mut key_reader);
      if let Ok(keys) = parsed_key {
        if !keys.is_empty() {
          if let Ok(signing_key) = RSASigningKey::new(&keys[0]) {
            let certified = CertifiedKey::new(chain, Arc::new(Box::new(signing_key)));
            return Some(certified);
          } else {
              if let Ok(k) = rustls::sign::any_ecdsa_type(&keys[0]) {
                  let certified = CertifiedKey::new(chain, Arc::new(k));
                  return Some(certified);
              } else {
                  error!("could not decode signing key (tried RSA and ECDSA)");
              }
          }
        }
      }
    }
  } else {
    error!("could not parse private key: {:?}", parsed_key);
  }

  None
}
