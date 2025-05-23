#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208741);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id("CVE-2024-43481", "CVE-2024-43612");
  script_xref(name:"IAVA", value:"2024-A-0643");

  script_name(english:"Security Update for Microsoft Power BI Report Server (October 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Power BI Report Server on the remote host is missing the October 2024 security update. It is, therefore,
affected by a server spoofing vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/power-bi/report-server/changelog#september-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f9ea088");
  # https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-43481
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb16d894");
  # https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-43612
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ebf95de");
  script_set_attribute(attribute:"solution", value:
"Upgrade Power BI Report Server to version 1.21.9032.4573 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:power_bi_report_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_power_bi_rs_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Power BI Report Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Microsoft Power BI Report Server', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:4);

var constraints = [
  { 'fixed_version' : '1.21.9032.4573' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
