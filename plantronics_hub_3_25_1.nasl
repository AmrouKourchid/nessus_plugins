#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187379);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/29");

  script_cve_id("CVE-2023-47270");
  script_xref(name:"IAVB", value:"2023-B-0103");

  script_name(english:"Plantronics Hub < 3.25.1 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"A peripheral control utility installed on the remote Windows host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Plantronics Hub installed on the remote Windows host is prior to 3.25.1. It is, therefore, affected by
a privilege escalation vulnerability in its updater system. Due to a race condition, a local attacker can set any
permissions on arbitrary files on an affected device. This can be used to run arbitrary code as the Microsoft Windows
SYSTEM account by overwriting existing binaries that are executed with SYSTEM privileges as part of the normal operation
of the device.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.hp.com/ie-en/document/ish_9869257-9869285-16/hpsbpy03895
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7fdfbcfc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Plantronics Hub version 3.25.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47270");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:plantronics:plantronics_hub");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_plantronics_hub_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/HP Plantronics Hub");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'HP Plantronics Hub', win_local:TRUE);

# Versions from google cache of release notes
# https://webcache.googleusercontent.com/search?q=cache:QrPgju7pKVIJ:https://support.poly.com/support/s/article/Hub-Release-Notes&hl=en&gl=ie
var constraints = [
  { 'max_version' : '3.25.53799.37131', 'fixed_version' : '3.25.54065.37203', 'fixed_display': '3.25.1 (3.25.54065.37203)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
