#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3208 ) exit(0);

include("compat.inc");

if (description)
{
  script_id(35291);
  script_version("1.34");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id("CVE-2004-2761", "CVE-2005-4900");
  script_bugtraq_id(11849, 33065);
  script_xref(name:"CERT", value:"836068");

  script_name(english:"SSL Certificate Signed Using Weak Hashing Algorithm");
  script_summary(english:"Checks signature algorithm used to sign SSL certificates in chain.");

  script_set_attribute(attribute:"synopsis", value:
"An SSL certificate in the certificate chain has been signed using a
weak hash algorithm.");
  script_set_attribute(attribute:"description", value:
"The remote service uses an SSL certificate chain that has been signed
using a cryptographically weak hashing algorithm (e.g. MD2, MD4, MD5,
or SHA1). These signature algorithms are known to be vulnerable to
collision attacks. An attacker can exploit this to generate another
certificate with the same digital signature, allowing an attacker to
masquerade as the affected service.

Note that this plugin reports all SSL certificate chains signed with
SHA-1 that expire after January 1, 2017 as vulnerable. This is in
accordance with Google's gradual sunsetting of the SHA-1 cryptographic
hash algorithm.

Note that certificates in the chain that are contained in the Nessus
CA database (known_CA.inc) have been ignored.");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc3279");
  # https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2008/961509
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9bb87bf2");
  # https://web.archive.org/web/20170429062248/http://www.phreedom.org/research/rogue-ca/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e120eea1");
  # https://security.googleblog.com/2014/09/gradually-sunsetting-sha-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d894816");
  # https://shattered.io
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51db68aa");
  # https://www.schneier.com/blog/archives/2005/02/cryptanalysis_o.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9dc7bfba");

  script_set_attribute(attribute:"solution", value:
"Contact the Certificate Authority to have the SSL certificate reissued.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-2761");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2004-2761");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);


  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ietf:md5");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ietf:x.509_certificate");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2009-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_certificate_chain.nasl");
  script_require_keys("SSL/Chain/WeakHash");

  exit(0);
}

include("ssl_funcs.inc");

# Get the port that has a weak hash algorithm from the KB.
var key = "SSL/Chain/WeakHash";
var port = get_kb_item_or_exit(key);
key += "/" + port;

# Get the list of certificates with weak hash algorithms.
var certs = get_kb_list_or_exit(key);

# Add the certificates to the report.
var attrs = make_list();

var attr;
foreach attr (certs)
{
  attrs = make_list(attrs, attr);
}

# Report our findings.
var report =
  '\nThe following certificates were part of the certificate chain sent by' +
  '\nthe remote host, but contain hashes that are considered to be weak.' +
  '\n' +
  '\n' + cert_report(attrs, chain:FALSE, bar:'');

security_report_v4(port: port, severity:SECURITY_WARNING , extra:report);
