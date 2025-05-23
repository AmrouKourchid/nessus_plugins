#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121046);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/09");

  script_cve_id("CVE-2018-3956", "CVE-2018-18688", "CVE-2018-18689");
  script_bugtraq_id(106798, 107496, 107552);

  script_name(english:"Foxit Reader < 9.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Foxit Reader installed on the remote Windows host is
prior to 9.4. It is, therefore, affected by multiple vulnerabilities:

  - An out-of-bounds read/write vulnerability and crash
    when handling XFA element attributes. (CVE-2018-3956)

  - A signature validation bypass vulnerability which
    could lead to incorrect validation results.
    (CVE-2018-18688, CVE-2018-18689)

  - Flaws in how PDF files are processed/handled could
    lead to arbitrary code execution. An attacker can 
    exploit this by convincing a user to open a specially
    crafted file in order to cause the execution of arbitrary
    code. (CVE-2019-6728,CVE-2019-6729)

Additionally, the application was affected by multiple potential 
information disclosure, denial of service, and remote code execution
vulnerabilities.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 9.4 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3956");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Foxit Reader', win_local:TRUE);

var constraints = [
  { 'max_version' : '9.3.0.10826', 'fixed_version' : '9.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
