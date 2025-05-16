##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162673);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2022-2274");
  script_xref(name:"IAVA", value:"2022-A-0265-S");

  script_name(english:"OpenSSL 3.0.4 < 3.0.5-dev Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 3.0.5-dev. It is, therefore, affected by a vulnerability
as referenced in the 3.0.5-dev advisory.

  - The OpenSSL 3.0.4 release introduced a serious bug in the RSA implementation for X86_64 CPUs supporting
    the AVX512IFMA instructions. This issue makes the RSA implementation with 2048 bit private keys incorrect
    on such machines and memory corruption will happen during the computation. As a consequence of the memory
    corruption an attacker may be able to trigger a remote code execution on the machine performing the
    computation. SSL/TLS servers or other servers using 2048 bit RSA private keys running on machines
    supporting AVX512IFMA instructions of the X86_64 architecture are affected by this issue. (CVE-2022-2274)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cve.org/CVERecord?id=CVE-2022-2274");
  # https://github.com/openssl/openssl/commit/4d8a88c134df634ba610ff8db1eb8478ac5fd345
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f3f91cd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 3.0.5-dev or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2274");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [{ 'min_version' : '3.0.4', 'fixed_version' : '3.0.5-dev'}];

vcf::openssl::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
