#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235080);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id(
    "CVE-2024-22351",
    "CVE-2025-25045",
    "CVE-2025-25046"
  );
  script_xref(name:"IAVB", value:"2025-B-0061");

  script_name(english:"IBM InfoSphere Information Server Multiple Vulnerabilities (April 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of IBM InfoSphere Information Server installed on the remote host is 11.7.x prior or equal to 11.7.1.6. It
is, therefore, potentially affected by multiple vulnerabilities:

  - IBM InfoSphere Information 11.7 Server does not invalidate session after logout which could allow an authenticated
    user to impersonate another user on the system. (CVE-2024-22351)

  - IBM InfoSphere Information 11.7 Server authenticated user to obtain sensitive information when a detailed technical
    error message is returned in a request. This information could be used in further attacks against the system.
    (CVE-2025-25045)

  - IBM InfoSphere Information Server 11.7 DataStage Flow Designer transmits sensitive information via URL or query
    parameters that could be exposed to an unauthorized actor using man in the middle techniques. (CVE-2025-25046)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7229921");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7231332");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7231333");
  script_set_attribute(attribute:"solution", value:
"Upgrade IBM InfoSphere Information Server based upon the guidance specified in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22351");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:infosphere_information_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_infosphere_information_server.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/IBM InfoSphere Information Server", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'IBM InfoSphere Information Server', win_local:TRUE);

# 11.7.1.6 requires an interim patch, so audit out if we're not paranoid
if (app_info.version == '11.7.1.6' && report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  { 'min_version':'11.7', 'max_version':'11.7.1.6', 'fixed_display':'11.7.1.6 with April 2025 Patch for DataStage Flow Designer' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
