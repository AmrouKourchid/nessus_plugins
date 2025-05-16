#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181289);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/14");

  script_cve_id("CVE-2023-4807");
  script_xref(name:"IAVA", value:"2023-A-0462-S");

  script_name(english:"OpenSSL 3.0.0 < 3.0.11 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 3.0.11. It is, therefore, affected by a vulnerability as
referenced in the 3.0.11 advisory.

  - Issue summary: The POLY1305 MAC (message authentication code) implementation contains a bug that might
    corrupt the internal state of applications on the Windows 64 platform when running on newer X86_64
    processors supporting the AVX512-IFMA instructions. Impact summary: If in an application that uses the
    OpenSSL library an attacker can influence whether the POLY1305 MAC algorithm is used, the application
    state might be corrupted with various application dependent consequences. The POLY1305 MAC (message
    authentication code) implementation in OpenSSL does not save the contents of non-volatile XMM registers on
    Windows 64 platform when calculating the MAC of data larger than 64 bytes. Before returning to the caller
    all the XMM registers are set to zero rather than restoring their previous content. The vulnerable code is
    used only on newer x86_64 processors supporting the AVX512-IFMA instructions. The consequences of this
    kind of internal application state corruption can be various - from no consequences, if the calling
    application does not depend on the contents of non-volatile XMM registers at all, to the worst
    consequences, where the attacker could get complete control of the application process. However given the
    contents of the registers are just zeroized so the attacker cannot put arbitrary values inside, the most
    likely consequence, if any, would be an incorrect result of some application dependent calculations or a
    crash leading to a denial of service. The POLY1305 MAC algorithm is most frequently used as part of the
    CHACHA20-POLY1305 AEAD (authenticated encryption with associated data) algorithm. The most common usage of
    this AEAD cipher is with TLS protocol versions 1.2 and 1.3 and a malicious client can influence whether
    this AEAD cipher is used by the server. This implies that server applications using OpenSSL can be
    potentially impacted. However we are currently not aware of any concrete application that would be
    affected by this issue therefore we consider this a Low severity security issue. As a workaround the
    AVX512-IFMA instructions support can be disabled at runtime by setting the environment variable
    OPENSSL_ia32cap: OPENSSL_ia32cap=:~0x200000 The FIPS provider is not affected by this issue.
    (CVE-2023-4807)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6754de4a121ec7f261b16723180df6592cbb4508
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eeb05f22");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-4807");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20230908.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/policies/secpolicy.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 3.0.11 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4807");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "openssl_version.nasl", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL", "Host/OS");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');


var os = get_kb_item_or_exit('Host/OS');
if ('windows' >!< tolower(os))
  audit(AUDIT_OS_NOT, 'Windows');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '3.0.0', 'fixed_version' : '3.0.11' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
