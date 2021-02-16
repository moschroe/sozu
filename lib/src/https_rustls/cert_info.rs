use rustls::Certificate;

/// Represents commonly used information about an X509 client.
#[derive(Debug)]
pub struct ClientCertSubject {
    pub opt_country: Option<String>,
    pub opt_state: Option<String>,
    pub opt_locality: Option<String>,
    pub opt_org: Option<String>,
    pub opt_org_unit: Option<String>,
    pub opt_common_name: Option<String>,
    pub opt_email: Option<String>,
}

/// Extracts all relevant fields of an X509 subject.
/// # Possible shortcomings
/// Only extracts first value of possibly multiple values for C, CN, OU, etc.
pub fn extract_subject(cert: &Certificate) -> Result<ClientCertSubject, String> {
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(&cert.0)
        .map_err(|err| format!("unable to parse cert: {}", err))?;
    let subject = parsed.subject();
    debug!("extracting subject of cert: {:#?}", subject);
    let opt_country= subject.iter_country().nth(0).and_then(|c|{
        c.as_str().map_err(|err|error!("client cert country is not valid UTF-8")).map(String::from).ok()
    });
    let opt_state= subject.iter_state_or_province().nth(0).and_then(|c|{
        c.as_str().map_err(|err|error!("client cert state is not valid UTF-8")).map(String::from).ok()
    });
    let opt_locality= subject.iter_locality().nth(0).and_then(|c|{
        c.as_str().map_err(|err|error!("client cert locality is not valid UTF-8")).map(String::from).ok()
    });
    let opt_org= subject.iter_organization().nth(0).and_then(|c|{
        c.as_str().map_err(|err|error!("client cert organization is not valid UTF-8")).map(String::from).ok()
    });
    let opt_org_unit= subject.iter_organizational_unit().nth(0).and_then(|c|{
        c.as_str().map_err(|err|error!("client cert org unit is not valid UTF-8")).map(String::from).ok()
    });
    let opt_common_name= subject.iter_common_name().nth(0).and_then(|c|{
        c.as_str().map_err(|err|error!("client cert common name is not valid UTF-8")).map(String::from).ok()
    });
    let opt_email= subject.iter_email().nth(0).and_then(|c|{
        c.as_str().map_err(|err|error!("client cert email is not valid UTF-8")).map(String::from).ok()
    });
    Ok(ClientCertSubject{
        opt_country,
        opt_state,
        opt_locality,
        opt_org,
        opt_org_unit,
        opt_common_name,
        opt_email
    })
}