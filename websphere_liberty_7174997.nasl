#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214870);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/01");

  script_cve_id("CVE-2024-40094");

  script_name(english:"IBM WebSphere Application Server Liberty 20.0.0.6 < 24.0.0.12 DoS (7174997)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a DoS vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Application Server Liberty running on the remote host is affected by a DoS vulnerability as
referenced in the 7174997 advisory.

  - GraphQL Java (aka graphql-java) before 21.5 does not properly consider ExecutableNormalizedFields (ENFs)
    as part of preventing denial of service via introspection queries. 20.9 and 19.11 are also fixed versions.
    (CVE-2024-40094)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7174997");
  script_set_attribute(attribute:"solution", value:
"Update to IBM WebSphere Application Server Liberty version 24.0.0.12 or later. Alternatively, upgrade to the minimal fix
pack levels required by the interim fix and then apply Interim Fix PH63673.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40094");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_liberty_detect.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');

var app = 'IBM WebSphere Application Server';
var app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if (app_info['Product'] != app + ' Liberty')
  audit(AUDIT_HOST_NOT, app + ' Liberty');

# If the detection is only remote, Source will be set, and we should require paranoia
var require_paranoid = FALSE;
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  require_paranoid = TRUE;

if ('PH63673' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

var constraints = [
  { 'min_version' : '20.0.0.6', 'fixed_version' : '24.0.0.12', 'fixed_display' : '24.0.0.12 or Interim Fix PH63673' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    require_paranoia:require_paranoid,
    severity:SECURITY_HOLE
);
