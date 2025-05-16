#TRUSTED b29a891be1f30a41b51a41283ac1690684d73c8626e4b01d7bba40eb90d82da7b211d7c58e8edf8d14266db7c5af17385b396a080b46b8a4df28a32634da7eda76ddab0291cc34dcf0f12fc4cb551fa41d0b320b655bc25950d82fd92da7b1597844771f37106227a1ca49cc48e8f7dd7d15ae816fba66caaabc9d8aae1121194995b571387b25e557c4bd8a826e2ca80f56f21abda40a8b30ebbeb256b2ba006d3dadd012007d4a4f2b9d180e210f5734617f7f844f53e52de9b7d5ca6f142c67779ec6d729c381003e8a022284f4535206176f419d224dc3d73d29cfd82ae3b76d0dd3801642d4dfee6b0992ed40538af8eb76913af6f02c74023d059424e4f64c9271ed0e408a0f02b51aa328fbf4aace028f8de80e3961a63beb18145fc11fba656bf73432f7a97848f53d56447d414dfcf3805de4604bf688e908ae3a1f644173d1f70b928e67f139d509de2bc23381387e9f4cc1d26904385c2e02748079d624b3040a6380b662e2f4e6e6c0758ac6938581dbff2fdc5b8286936b58625280a6ae952cc6e684a80769208a47fb30aa47b0df709065c4b0aaa079fff9aff8109816fecc58c3b5be3d633aaa98eed262165543122f55ce13c27f5369c2c7a3de4427780ab168bc43d718afb421a20fb02d0b9d52a43110a6c1aa17c964591496000ea98ebac7a51cf3afd0f1b09109960d43ccc27e4e783bf473e50b5e19
#TRUST-RSA-SHA256 8a8404983504ceedb2c2892cff92312088d95eb3fe17909b00e9e72a4c8a69387df52c47db7daba86d4d3a7c346c578162899d01c5ffe11fe70238b663af9293bcc10072c53795558a496298b9320fb8c1bcc4e5365a83793d169940f1f3bfc42ec8d4c0aaebd742922c483d5971261db3092ed7db003634df7103080518c4217924adb3d1388caf7c99ea8cdf0d633f89393ddbeb05c22b51cd6d5862a02509c0a8894f48d41914d300300feabac506a857d95cd78050be25795be7ff4187549ba784effe5c809d188a4637185987f4929ee1a55e5553611351b31b697e44d3a0b0563a733f18090349e766a1d2aaf54d81cc72488636c338592cf5416724846d15db06596260ad36bc7067c037831f44157c072c5a58255e9210bc1bfe98951a4ad2747286edc778c85d8d924309e54ad0bb4e45aac129e6f63ff2232f8fda7e9dfe80f9717fc0ac6721d381d172859dc743935c0a1100a64bc02cf4d4fefc035e8e146fb28e786af6753e8be070b439268c58402bfe13b91f93614d8e6cf3badecb5948fbcc1b54c073cf65493c2981750dc7e6d26a19c4364f0e7c2650abac1a54483d6431336a90e54bf8694dbe5635f4de69f55d860e79a7a6441b281fd29bfea24da6abadb4456aa3de25b4cb9510a4075587267df4bf53bf8a1435191baca2bf5df03aab28aa236fcef6526196a5438f66aaacad16a6602c28bf7792
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103864);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2017-15361");
  script_xref(name:"IAVA", value:"2017-A-0313");

  script_name(english:"SSL Certificate Contains Weak RSA Key (Infineon TPM / ROCA)");
  script_summary(english:"Checks that the certificate chain has no weak RSA keys");

  script_set_attribute(attribute:"synopsis", value:
"The X.509 certificate chain used by this service contains certificates
with RSA keys that may have been improperly generated.");
  script_set_attribute(attribute:"description", value:
"At least one of the X.509 certificates sent by the remote host has an RSA key
that appears to be generated improperly, most likely by a TPM (Trusted Platform
Module) produced by Infineon Technologies.
A third party may be able to recover the private key from the certificate's
public key. This may allow an attacker to impersonate an HTTPS website or
decrypt SSL/TLS sessions to the remote service.");
  script_set_attribute(attribute:"see_also", value:"https://crocs.fi.muni.cz/public/papers/rsa_ccs17");
  # https://www.infineon.com/cms/en/product/promopages/rsa-update/?redirId=59206
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9357cd2f");
  # https://sites.google.com/a/chromium.org/dev/chromium-os/tpm_firmware_update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3495f5d8");
  script_set_attribute(attribute:"see_also", value:"https://support.hp.com/us-en/document/c05792935");
  script_set_attribute(attribute:"see_also", value:"https://support.lenovo.com/us/en/product_security/len-15552");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV170012
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b614caf");
  script_set_attribute(attribute:"solution", value:
"Upgrade the firmware for all Infineon TPMs and revoke the affected
certificates, including any certificates signed by an affected key.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15361");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_certificate_chain.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");
include("x509_func.inc");
include("byte_func.inc");

PRINTS = [
  '6',
  '1e',
  '7e',
  '402',
  '161a',
  '1a316',
  '30af2',
  '7ffffe',
  '1ffffffe',
  '7ffffffe',
  '4000402',
  '1fffffffffe',
  '7fffffffffe',
  '7ffffffffffe',
  '12dd703303aed2',
  '7fffffffffffffe',
  '1434026619900b0a',
  '7fffffffffffffffe',
  '1164729716b1d977e',
  '147811a48004962078a',
  'b4010404000640502',
  '7fffffffffffffffffffe',
  '1fffffffffffffffffffffe',
  '1000000006000001800000002',
  '1ffffffffffffffffffffffffe',
  '16380e9115bd964257768fe396',
  '27816ea9821633397be6a897e1a',
  '1752639f4e85b003685cbe7192ba',
  '1fffffffffffffffffffffffffffe',
  '6ca09850c2813205a04c81430a190536',
  '7fffffffffffffffffffffffffffffffe',
  '1fffffffffffffffffffffffffffffffffe',
  '7fffffffffffffffffffffffffffffffffe',
  '1ffffffffffffffffffffffffffffffffffffe',
  '50c018bc00482458dac35b1a2412003d18030a',
  '161fb414d76af63826461899071bd5baca0b7e1a',
  '7fffffffffffffffffffffffffffffffffffffffe',
  '7ffffffffffffffffffffffffffffffffffffffffe'
];
# Decode these as bigints just once
for (i = 0; i < max_index(PRINTS); ++i)
  PRINTS[i] = bn_hex2raw(PRINTS[i]);

# This is parallel to the PRINTS list, above... first element here is
# used with first element of PRINTS, etc.
PRIMES = [
  3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
  71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
  149, 151, 157, 163, 167
];

function roca_check_modulus(n)
{
  local_var i, finger, bitmask;

  # Borrows the detection method from https://github.com/crocs-muni/roca
  # Try all primes and their fingerprints
  for (i = 0; i < max_index(PRINTS); ++i)
  {
    finger = bn_lshift_one(count:int(bn_raw2dec(bn_mod(n, bn_dec2raw(PRIMES[i])))));
    # Check if any of the bits in the fingerprint are present
    bitmask = bn_and(a:finger, b:PRINTS[i]);
    if (bn_cmp(key1:bitmask, key2:bn_dec2raw("0")) == 0)
      return FALSE;
  }

  return TRUE;
}

# Shifts the number `1` left by up to a few hundred bits, such as `1 << 64`,
# returning a bignum. Basically implements 1 * 2**y, but is faster than
# doing an exponent.
# OpenSSL recommending using BN_lshift, but NASL doesn't have this.
function bn_lshift_one(count)
{
  local_var bytes;

  bytes = crap(data:'\x00', length:(count / 8) + 1);
  # Set the single bit that we care about
  bytes[0] = raw_string(1 << (count % 8));

  return bytes;
}

# Performs bitwise-AND of two bignums. They do not have to be the
# same length
function bn_and(a, b)
{
  local_var a_len, b_len, max, ret;

  a_len = strlen(a);
  b_len = strlen(b);
  if (a_len > b_len)
    max = a_len;
  else
    max = b_len;

  # Pad out whichever is shorter than the other
  if (a_len < max)
    a = crap(data:'\x00', length:max - a_len) + a;
  if (b_len < max)
    b = crap(data:'\x00', length:max - b_len) + b;

  # Do the ANDing
  ret = crap(data:'\x00', length:max);
  for (i = 0; i < max; ++i)
    ret[i] = mkbyte(ord(a[i]) & ord(b[i]));

  return ret;
}

###
# Main part of the script
###

port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(0, "No SSL services were detected");

# Gather up the certs from SNI and non-SNI connections

certs = [];

sni_certs = get_server_cert(port:port, getchain:TRUE, encoding:"der", sni:TRUE);
if (!isnull(sni_certs))
  certs = make_list(certs, sni_certs);

other_certs = get_server_cert(port:port, getchain:TRUE, encoding:"der", sni:FALSE);
if (!isnull(other_certs))
  certs = make_list(certs, other_certs);

certs = list_uniq(certs);

results = "";
unparsed = 0;
nonrsa = 0;
foreach cert (certs)
{
  parsed = parse_der_cert(cert:cert);
  # If we couldn't parse the certificate or if it's not an RSA public key
  if (isnull(parsed))
  {
    unparsed++;
    continue;
  }

  if (empty_or_null(parsed.tbsCertificate.subjectPublicKeyInfo) || "RSA" >!< oid_name[parsed.tbsCertificate.subjectPublicKeyInfo[0]])
  {
    nonrsa++;
    continue;
  }

  if (!empty_or_null(parsed.tbsCertificate.subjectPublicKeyInfo[1]) && roca_check_modulus(n:parsed.tbsCertificate.subjectPublicKeyInfo[1][0]))
    results += " - Subject: " + format_dn(parsed.tbsCertificate.subject) + '\n';
}

if (results != "")
{
  security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    extra:'The following certificates appear to be affected :\n' + results
  );
}
else
{
  exit(0, "None of the " + max_index(certs) + " certificates on port " + port + " appear to have an affected public key (unparsable: " + unparsed + ", non-RSA: " + nonrsa + ").");
}
