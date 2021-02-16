use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use std::io::BufReader;
use webpki;
use rustls::{ResolvesServerCert, RootCertStore, ClientCertVerifier, ClientCertVerified, DistinguishedNames, TLSError, Certificate, AllowAnyAuthenticatedClient, ClientHello};
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

pub struct DynamicClientCertificateVerifierWrapper(RwLock<DynamicClientCertificateVerifier>);

impl ClientCertVerifier for DynamicClientCertificateVerifierWrapper {
  fn client_auth_root_subjects(&self, opt_sni: Option<&webpki::DNSName>) -> Option<DistinguishedNames> {
    let access_read = self.0.read().expect("lock poisoned, unrecoverable program state");
    if access_read.passthrough {
        return None;
    }
    // access_read.inner.client_auth_root_subjects()
    if let Some(sni) = opt_sni {
      // eprintln!("client_auth_root_subjects({:?})", sni);
      let snistr: &str = sni.as_ref().into();
      if let Some((key, fp)) = access_read.domains.domain_lookup(snistr.as_bytes(), true) {
        let verifier = access_read.inners.get(fp).expect("inconsistent state, inners should contain domain fingerprint!");
        let res = verifier.client_auth_root_subjects(opt_sni);
        // eprintln!("client_auth_root_subjects() -> {:?}", res);
        res
      } else {
        error!("unable to find root for domain {:?}", snistr);
        None
      }
    } else {
      warn!("no SNI, unable to look up client ca");
      None
    }
  }

  // fn verify_client_cert(&self, presented_certs: &[Certificate]) -> Result<ClientCertVerified, TLSError>
  fn verify_client_cert(&self,
                        presented_certs: &[Certificate],
                        opt_sni: Option<&webpki::DNSName>) -> Result<ClientCertVerified, TLSError>
  {
    let access_read = self.0.read().map_err(|err_rwlock| {
      error!("unable to acquire RwLock on inner DynamicClientCertificateVerifier in verify_client_cert(), returning Err");
      TLSError::General("internal error in client cert verifier".into())
    })?;
    if access_read.passthrough {
      return Ok(ClientCertVerified::assertion());
    }
    // access_read.inner.verify_client_cert(presented_certs)
    if let Some(sni) = opt_sni {
      // eprintln!("verify_client_cert({:?})", sni);
      let snistr: &str = sni.as_ref().into();
      if let Some((key, fp)) = access_read.domains.domain_lookup(snistr.as_bytes(), true) {
        let verifier = access_read.inners.get(fp).expect("inconsistent state, inners should contain domain fingerprint!");
        // eprintln!("presented_certs: {:?}", presented_certs);
        let res = verifier.verify_client_cert(presented_certs, opt_sni);
        eprintln!("verify_client_cert() -> {:?}", res.is_ok());
        res
        // unimplemented!();
      } else {
        error!("unable to find root for domain {:?}", snistr);
        Err(TLSError::General(format!("unable to find root for domain {:?}", snistr)))
      }
    } else {
      warn!("no SNI, unable to look up client ca");
      Err(TLSError::General(format!("no SNI, unable to look up client ca")))
    }
  }
}

impl DynamicClientCertificateVerifierWrapper {
  pub fn in_arc(passthrough: bool) -> Arc<Self> {
    Arc::new(DynamicClientCertificateVerifierWrapper(RwLock::new(DynamicClientCertificateVerifier::new(passthrough))))
  }

  pub fn add_client_ca(&self, add: AddClientCa) -> Result<CertificateFingerprint, String> {
    let mut access_write = self.0.write().expect("lock poisoned, unrecoverable program state");
    access_write.add_client_ca(add)
  }

  pub fn remove_client_ca(&self, remove: RemoveClientCa) -> Result<(), String> {
    let mut access_write = self.0.write().expect("lock poisoned, unrecoverable program state");
    access_write.remove_client_ca(remove)
  }
}

type ARCVerifier=Arc<(dyn ClientCertVerifier + 'static)>;

pub struct DynamicClientCertificateVerifier {
  domains:  TrieNode<CertificateFingerprint>,
  roots: HashMap<CertificateFingerprint, rustls::Certificate>,
  // inner: Arc<(dyn ClientCertVerifier + 'static)>,
  inners: HashMap<CertificateFingerprint, ARCVerifier>,
  /// Signals NOP mode where no checks are performed but the verifier has already been passed to
  /// rustls.
  passthrough: bool,
}

impl DynamicClientCertificateVerifier {
  fn new(passthrough: bool) -> Self {
    let roots = RootCertStore::empty();
    DynamicClientCertificateVerifier {
      domains: TrieNode::root(),
      roots: HashMap::new(),
      // inner: AllowAnyAuthenticatedClient::new(roots),
      inners: Default::default(),
      passthrough
    }
  }

  fn add_client_ca(&mut self, add: AddClientCa) -> Result<CertificateFingerprint, String> {
    debug!("adding client ca: {:?}", add);
    let mut rdr_cert = BufReader::new(add.certificate.as_bytes());
    let mut certs = match pemfile::certs(&mut rdr_cert) {
      Ok(cert) => cert,
      Err(err) => {
        return Err(format!("unable to parse client ca cert: {:?}", err));
      }
    };
    let cert;
    if let Some(first_cert) = certs.pop() {
      cert = first_cert;
    } else {
      return Err(format!("unable to parse exactly one cert from provided client CA data, got {}", certs.len()));
    };
    if certs.len() > 0 {
      return Err(format!("unable to parse exactly one cert from provided client CA data, got {}", certs.len() + 1));
    }
    std::mem::drop(certs);
    let fp = CertificateFingerprint(calculate_fingerprint_from_der(&cert.0));

    let mut new_cert_store = RootCertStore::empty();
    new_cert_store.add(&cert);

    self.roots.insert(fp.clone(), cert);
    for dom in add.names {
      self.domains.domain_insert(dom.into_bytes(), fp.clone());
    }

    // eprintln!("sadfasf: {:?}", self.domains);
    // eprintln!("sadfasf: {:?}", self.roots);
    use std::collections::hash_map::Entry;
    let verifier_new=AllowAnyAuthenticatedClient::new(new_cert_store);
    match self.inners.entry(fp.clone()) {
      Entry::Occupied(mut enoc)=>{
        enoc.insert(verifier_new);
      }
      Entry::Vacant(envac)=>{
        envac.insert(verifier_new);
      }
    }

    // let mut new_roots = RootCertStore::empty();
    // if let Err(err) = new_roots.add(&cert) {
    //   return Err(format!("unable to add new client CA to RootCertStore: {}", err));
    // };
    // self.add_all_roots(&mut new_roots)?;
    // self.roots.insert(fp.clone(), cert);
    // // make new verifier
    // self.inner = AllowAnyAuthenticatedClient::new(new_roots)

    // enable checks
    self.passthrough = false;
    Ok(fp)
  }

  fn remove_client_ca(&mut self, remove: RemoveClientCa) -> Result<(), String> {
    unimplemented!();
    // trace!("removing client ca");
    // self.roots.remove(&remove.fingerprint).ok_or_else(|| format!("no client ca cert with given fingerprint found to remove"))?;
    // let mut new_roots = RootCertStore::empty();
    // self.add_all_roots(&mut new_roots)?;
    // self.inner = AllowAnyAuthenticatedClient::new(new_roots);
    // Ok(())
  }

  fn add_all_roots(&mut self, new_roots: &mut RootCertStore) -> Result<(), String> {
    for cert in self.roots.values() {
      if let Err(err) = new_roots.add(cert) {
        return Err(format!("unable to add existing client CA to RootCertStore: {}", err));
      };
    }
    Ok(())
  }
}

impl ClientCertVerifier for DynamicClientCertificateVerifier {
  fn client_auth_root_subjects(&self, sni: Option<&webpki::DNSName>) -> Option<DistinguishedNames> {
    unimplemented!();
    // self.inner.client_auth_root_subjects(sni)
  }

  fn verify_client_cert(&self,
                        presented_certs: &[Certificate],
                        sni: Option<&webpki::DNSName>) -> Result<ClientCertVerified, TLSError> {
    unimplemented!();
    // self.inner.verify_client_cert(presented_certs,sni)
  }
}

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
