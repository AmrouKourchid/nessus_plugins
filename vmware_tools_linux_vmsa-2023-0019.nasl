#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186616);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2023-20900");
  script_xref(name:"VMSA", value:"2023-0019");
  script_xref(name:"IAVA", value:"2023-A-0450-S");

  script_name(english:"VMware Tools for Linux 10.3.x < 10.3.26 Authentication Bypass (VMSA-2023-0019)");

  script_set_attribute(attribute:"synopsis", value:
"The virtualization tool suite is installed on the remote Linux host is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Tools installed on the remote Linux host is 10.3.x prior to 10.3.26. It is, therefore, affected
by a SAML token signature bypass vulnerability. A malicious attacker with man-in-the-middle network positioning in the
virtual machine network can bypass SAML token signature verification resulting in being able to perform VMware Tools
Guest Operations.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2023-0019.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Tools version 10.3.26 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20900");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:tools");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "vmware_tools_nix_installed.nbin");
  script_require_keys("Host/OS/uname", "installed_sw/VMware Tools");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit("Host/OS/uname");

var app_info = vcf::get_app_info(app:'VMware Tools');
var constraints = [{ 'min_version' : '10.3', 'fixed_version' : '10.3.26' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

