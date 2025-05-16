#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234896);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

  script_cve_id("CVE-2025-1094");

  script_name(english:"Tenable Security Center SQLI (TNS-2025-06)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Security Center installed on the remote system is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Security Center running on the remote host is version 6.5.0 or 6.5.1. It is,
therefore, affected by a vulnerability as referenced in the TNS-2025-06 advisory.

  - Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(),
    PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to
    achieve SQL injection in certain usage patterns. Specifically, SQL injection requires the application to
    use the function result to construct input to psql, the PostgreSQL interactive terminal. Similarly,
    improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source of
    command line arguments to achieve SQL injection when client_encoding is BIG5 and server_encoding is one of
    EUC_TW or MULE_INTERNAL. Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.
    (CVE-2025-1094)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.tenable.com/release-notes/Content/security-center/2025.htm#2025043
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a413c3f2");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2025-06");
  script_set_attribute(attribute:"solution", value:
"Apply Patch SC-202504.3");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1094");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:security_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("installed_sw/SecurityCenter");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::tenable_sc::get_app_info();

var patches = make_list("SC-202504.3");
vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
  { 'equal' : '6.5.0', 'fixed_display' : 'Upgrade to 6.5.1 and then apply Patch SC-202504.3' },
  { 'equal' : '6.5.1', 'fixed_display' : 'Apply Patch SC-202504.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'sqli':TRUE}
);
