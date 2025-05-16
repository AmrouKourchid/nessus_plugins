#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232852);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id("CVE-2025-21104");
  script_xref(name:"IAVA", value:"2025-A-0185");

  script_name(english:"Dell EMC NetWorker Open Redirect (DSA-2025-124)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by an open redirect vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Dell EMC NetWorker installed on the remote Windows host is affected by an Open Redirect Vulnerability 
in NMC. An unauthenticated attacker with remoter access could potentially exploit this vulnerability, leading to a 
targeted application user being redirected to arbitrary web URLs. The vulnerability could be leveraged by attackers to 
conduct phishing attacks that cause users to divulge sensitive information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000294392/dsa-2025-124-security-update-for-dell-networker-management-console-for-http-host-header-injection-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15bdf940");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell EMC NetWorker 19.11.0.4 or later or see vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21104");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:emc_networker");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'EMC NetWorker', win_local:TRUE);

if (app_info['Management Console Installed'] == FALSE)

  audit(AUDIT_INST_PATH_NOT_VULN, 'EMC NetWorker', app_info.version, app_info.path);

var constraints = [
  { 'fixed_version' : '19.11.0.4' },
  { 'equal': '19.12', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

