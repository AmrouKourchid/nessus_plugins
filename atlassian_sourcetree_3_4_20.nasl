#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211730);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/12");

  script_cve_id("CVE-2024-21697");
  script_xref(name:"IAVA", value:"2024-A-0759");

  script_name(english:"Atlassian SourceTree 3.4.19 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian SourceTree installed on the remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian SourceTree installed on the remote Windows host is version 3.4.19. It is, therefore, affected
by a remote code execution vulnerability. An attacker, with the interaction of an authorized user, can execute arbitrary
code on the affected host.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/SRCTREE-8168");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian SourceTree 3.4.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21697");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:sourcetree");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("atlassian_sourcetree_detect.nbin");
  script_require_keys("installed_sw/SourceTree", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf_extras.inc");
get_kb_item_or_exit("SMB/Registry/Enumerated");
#atlassian_sourcetree add conversions for b --> beta and a --> alpha
vcf::atlassian_sourcetree::initialize();

var app_info = vcf::get_app_info(app:'SourceTree', win_local:TRUE);
var constraints = [{ 'min_version' : '3.4.19', 'fixed_version' : '3.4.20' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
