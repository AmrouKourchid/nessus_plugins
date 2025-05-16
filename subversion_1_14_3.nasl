#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(208749);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/12");

  script_cve_id("CVE-2024-45720");
  script_bugtraq_id(106770);
  script_xref(name:"IAVA", value:"2024-A-0640");

  script_name(english:"Apache Subversion < 1.14.4");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Subversion is prior to 1.14.4 and is, therefore,
  affected by a vulnerability that may lead to unexpected command line argument interpretation,
  including argument injection and execution of other programs, if a
  specially crafted command line argument string is processed.");
  script_set_attribute(attribute:"see_also", value:"https://subversion.apache.org/security/CVE-2024-45720-advisory.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Subversion 1.14.4 or later, or apply the vendor-supplied patch or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45720");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("subversion_installed.nasl");
  script_require_keys("installed_sw/Subversion Server", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::get_app_info(app:"Subversion Client");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  { "fixed_version" : "1.14.4" }
];

vcf::apache_subversion::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
