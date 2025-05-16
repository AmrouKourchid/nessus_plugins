#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232824);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/15");

  script_cve_id("CVE-2024-47535");

  script_name(english:"IBM WebSphere eXtreme Scale 8.6.1 < 8.6.1.6 DoS (7185951)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere eXtreme Scale installed on the remote host is prior to 8.6.1.6 IBM. It is, therefore,
affected by a vulnerability as referenced in the 7185951 advisory.

  - Netty is an asynchronous event-driven network application framework for rapid development of maintainable
    high performance protocol servers & clients. An unsafe reading of environment file could potentially cause
    a denial of service in Netty. When loaded on an Windows application, Netty attempts to load a file that
    does not exist. If an attacker creates such a large file, the Netty application crashes. This
    vulnerability is fixed in 4.1.115. (CVE-2024-47535)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7185951");
  script_set_attribute(attribute:"solution", value:
"Please see vendor advisory for details.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47535");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_extreme_scale");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '8.6.1', 'fixed_version' : '8.6.1.6', 'missing_patch' : 'PH65615', 'fixed_display' : 'Please see vendor advisory for details.' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
