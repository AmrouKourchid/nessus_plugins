#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216076);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id("CVE-2024-45336", "CVE-2024-45341");
  script_xref(name:"IAVB", value:"2025-B-0010-S");

  script_name(english:"Golang 1.22 < 1.22.11 / 1.23 < 1.23.5 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macoOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Golang running on the remote host is 1.24 prior to 1.24rc2. It is, therefore, is affected by
multiple vulnerabilities:

  - net/http: Sensitive headers are incorrectly sent after cross-domain redirect (CVE-2024-45336)

  - crypto/x509: usage of IPv6 zone IDs can bypass URI name constraints (CVE-2024-45341)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/g/golang-announce/c/sSaUhLA-2SI?pli=1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Golang Go version 1.22.11, 1.23.5, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45336");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-45341");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:golang:go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("golang_macos_installed.nbin");
  script_require_keys("installed_sw/Golang Go Programming Language", "Host/MacOSX/Version");
  script_exclude_keys("SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Golang Go Programming Language');

var constraints = [
  { 'min_version' : '1.22', 'fixed_version' : '1.22.11' },
  { 'min_version' : '1.23', 'fixed_version' : '1.23.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
