#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186819);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/14");

  script_cve_id("CVE-2023-22524");

  script_name(english:"Atlassian Confluence < Companion-2.0.0 / < Companion-2.0.1 (CONFSERVER-93518)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-93518 advisory.

  - RCE Vulnerability in Atlassian Companion App for MacOS (CVE-2023-22524)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-93518");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version Companion-2.0.0, Companion-2.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22524");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:companion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_atlassian_companion_installed.nbin");
  script_require_keys("installed_sw/Atlassian Companion");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Atlassian Companion');

var constraints = [
  { 'fixed_version' : '2.0.0', 'fixed_display' : 'Companion-2.0.0 / Companion-2.0.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
