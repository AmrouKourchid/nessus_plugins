#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201104);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id("CVE-2024-29131", "CVE-2024-29133");

  script_name(english:"IBM WebSphere eXtreme Scale 8.6.1.0 < 8.6.1.6 (7150045)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere eXtreme Scale installed on the remote host is prior to 8.6.1.6 IBM. It is, therefore,
affected by multiple vulnerabilities as referenced in the 7150045 advisory.

  - Out-of-bounds Write vulnerability in Apache Commons Configuration.This issue affects Apache Commons
    Configuration: from 2.0 before 2.10.1. Users are recommended to upgrade to version 2.10.1, which fixes the
    issue. (CVE-2024-29131, CVE-2024-29133)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7150045");
  script_set_attribute(attribute:"solution", value:
"Please see vendor advisory for details.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29133");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-29131");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_extreme_scale");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_websphere_extreme_scale_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere eXtreme Scale", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'IBM WebSphere eXtreme Scale');

var components = app_info['Components'];
if ('Liberty Deployment' >!< components)
    audit(AUDIT_NOT_INST, 'IBM WebSphere eXtreme Scale Liberty Deployment');

if (app_info['version'] =~ "^8\.6\.1" && report_paranoia < 2)
    audit(AUDIT_PARANOID);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '8.6.1.0', 'fixed_version' : '8.6.1.6', 'missing_patch' : 'PH61029', 'fixed_display' : 'Please see vendor advisory for details.' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
