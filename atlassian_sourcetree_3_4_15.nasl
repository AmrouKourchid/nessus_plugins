#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183502);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/01");

  script_cve_id("CVE-2023-22514");
  script_xref(name:"IAVA", value:"2023-A-0569-S");

  script_name(english:"Atlassian SourceTree 3.4.14 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian SourceTree installed on the remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian SourceTree installed on the remote Windows host is version 3.4.14. It is, therefore, affected
by a remote code execution vulnerability. An attacker, with the interaction of an authorized user, can execute arbitrary
code on the affected host.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/SRCTREE-8076");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian SourceTree 3.4.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22514");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:sourcetree");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is This script is Copyright (C) 2023-2025 20i23 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("atlassian_sourcetree_detect.nbin");
  script_require_keys("installed_sw/SourceTree");

  exit(0);
}

include("vcf_extras.inc");

#atlassian_sourcetree add conversions for b --> beta and a --> alpha
vcf::atlassian_sourcetree::initialize();

var app_info = vcf::get_app_info(app:"SourceTree");
var constraints = [{ "equal" : "3.4.14", "fixed_version" : "3.4.15" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
