#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235721);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/12");

  script_cve_id("CVE-2020-29574");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/27");

  script_name(english:"Sophos Cyberoam SQLi (CVE-2020-29574)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is potentially missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Sophos Cyberoam installed on the remote host is potentially affected by an SQL injection vulnerability.
An SQL injection vulnerability in the WebAdmin of Cyberoam OS through 2020-12-04 allows unauthenticated attackers to
execute arbitrary SQL statements remotely.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.bleepingcomputer.com/news/security/sophos-fixes-sql-injection-vulnerability-in-their-cyberoam-os/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d91aaea");
  # https://support.sophos.com/support/s/article/KBA-000007526?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11d4d792");
  script_set_attribute(attribute:"solution", value:
"Cyberoam is no longer supported . Upgrade to a supported product.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29574");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sophos:cyberoamos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sophos_cyberoamos_web_detect.nbin");
  script_require_keys("installed_sw/Sophos CyberoamOS",  "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::combined_get_app_info(app:'Sophos CyberoamOS');

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '9999999.999999', 'fixed_display':'See vendor EOL advisory' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
