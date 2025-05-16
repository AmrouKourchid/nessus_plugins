#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201946);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/13");

  script_cve_id(
    "CVE-2023-0464",
    "CVE-2023-0465",
    "CVE-2023-0466",
    "CVE-2023-2650",
    "CVE-2023-3446",
    "CVE-2023-3817",
    "CVE-2023-4807",
    "CVE-2023-5678",
    "CVE-2023-46218",
    "CVE-2023-46219",
    "CVE-2024-0727",
    "CVE-2024-2004",
    "CVE-2024-2398",
    "CVE-2024-21892",
    "CVE-2024-22017",
    "CVE-2024-22025",
    "CVE-2024-27983",
    "CVE-2024-32974",
    "CVE-2024-32975",
    "CVE-2024-32976",
    "CVE-2024-34362",
    "CVE-2024-34363",
    "CVE-2024-34364"
  );

  script_name(english:"Tenable.ad < 3.59.5 Multiple Vulnerabilities (TNS-2024-11)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Tenable.ad installed on the remote host is prior to 3.59.5. It is, therefore, affected by multiple
vulnerabilities as referenced in the TNS-2024-11 advisory.

  - The POLY1305 MAC (message authentication code) implementation contains a bug that might
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

  - Envoy is a cloud-native, open source edge and service proxy. Envoyproxy with a Brotli filter can get into
    an endless loop during decompression of Brotli data with extra input. (CVE-2024-32976)

  - Envoy is a cloud-native, open source edge and service proxy. Envoy exposed an out-of-memory (OOM) vector
    from the mirror response, since async HTTP client will buffer the response with an unbounded buffer.
    (CVE-2024-34364)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2024-11");
  script_set_attribute(attribute:"solution", value:
"Upgrade Tenable.ad based upon the guidance specified in TNS-2024-11.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21892");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:tenable_identity_exposure");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:tenable_ad");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ad_win_installed.nbin", "tenable_ad_web_detect.nbin");
  script_require_keys("installed_sw/Tenable.ad");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Tenable.ad');

var constraints = [ { 'fixed_version' : '3.59.5' } ];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
