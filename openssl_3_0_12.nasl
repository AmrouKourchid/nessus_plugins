#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183891);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2023-5363", "CVE-2023-6129");
  script_xref(name:"IAVA", value:"2023-A-0582-S");

  script_name(english:"OpenSSL 3.0.0 < 3.0.12 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 3.0.12. It is, therefore, affected by multiple
vulnerabilities as referenced in the 3.0.12 advisory.

  - Issue summary: The POLY1305 MAC (message authentication code) implementation contains a bug that might
    corrupt the internal state of applications running on PowerPC CPU based platforms if the CPU provides
    vector instructions. Impact summary: If an attacker can influence whether the POLY1305 MAC algorithm is
    used, the application state might be corrupted with various application dependent consequences. The
    POLY1305 MAC (message authentication code) implementation in OpenSSL for PowerPC CPUs restores the
    contents of vector registers in a different order than they are saved. Thus the contents of some of these
    vector registers are corrupted when returning to the caller. The vulnerable code is used only on newer
    PowerPC processors supporting the PowerISA 2.07 instructions. The consequences of this kind of internal
    application state corruption can be various - from no consequences, if the calling application does not
    depend on the contents of non-volatile XMM registers at all, to the worst consequences, where the attacker
    could get complete control of the application process. However unless the compiler uses the vector
    registers for storing pointers, the most likely consequence, if any, would be an incorrect result of some
    application dependent calculations or a crash leading to a denial of service. The POLY1305 MAC algorithm
    is most frequently used as part of the CHACHA20-POLY1305 AEAD (authenticated encryption with associated
    data) algorithm. The most common usage of this AEAD cipher is with TLS protocol versions 1.2 and 1.3. If
    this cipher is enabled on the server a malicious client can influence whether this AEAD cipher is used.
    This implies that TLS server applications using OpenSSL can be potentially impacted. However we are
    currently not aware of any concrete application that would be affected by this issue therefore we consider
    this a Low severity security issue. (CVE-2023-6129)

  - Issue summary: A bug has been identified in the processing of key and initialisation vector (IV) lengths.
    This can lead to potential truncation or overruns during the initialisation of some symmetric ciphers.
    Impact summary: A truncation in the IV can result in non-uniqueness, which could result in loss of
    confidentiality for some cipher modes. When calling EVP_EncryptInit_ex2(), EVP_DecryptInit_ex2() or
    EVP_CipherInit_ex2() the provided OSSL_PARAM array is processed after the key and IV have been
    established. Any alterations to the key length, via the keylen parameter or the IV length, via the
    ivlen parameter, within the OSSL_PARAM array will not take effect as intended, potentially causing
    truncation or overreading of these values. The following ciphers and cipher modes are impacted: RC2, RC4,
    RC5, CCM, GCM and OCB. For the CCM, GCM and OCB cipher modes, truncation of the IV can result in loss of
    confidentiality. For example, when following NIST's SP 800-38D section 8.2.1 guidance for constructing a
    deterministic IV for AES in GCM mode, truncation of the counter portion could lead to IV reuse. Both
    truncations and overruns of the key and overruns of the IV will produce incorrect results and could, in
    some cases, trigger a memory exception. However, these issues are not currently assessed as security
    critical. Changing the key and/or IV lengths is not considered to be a common operation and the vulnerable
    API was recently introduced. Furthermore it is likely that application developers will have spotted this
    problem during testing since decryption would fail unless both peers in the communication were similarly
    vulnerable. For these reasons we expect the probability of an application being vulnerable to this to be
    quite low. However if an application is vulnerable then this issue is considered very serious. For these
    reasons we have assessed this issue as Moderate severity overall. The OpenSSL SSL/TLS implementation is
    not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers are not affected by this because the
    issue lies outside of the FIPS provider boundary. OpenSSL 3.1 and 3.0 are vulnerable to this issue.
    (CVE-2023-5363)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/openssl/openssl/commit/0df40630850fb2740e6be6890bb905d3fc623b2d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?608327d1");
  # https://github.com/openssl/openssl/commit/050d26383d4e264966fb83428e72d5d48f402d35
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71a978e4");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-5363");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-6129");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 3.0.12 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5363");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '3.0.0', 'fixed_version' : '3.0.12' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
