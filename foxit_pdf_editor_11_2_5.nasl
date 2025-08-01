#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172255);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id(
    "CVE-2022-43649",
    "CVE-2023-27329",
    "CVE-2023-27330",
    "CVE-2023-27331"
  );
  script_xref(name:"IAVA", value:"2023-A-0128-S");

  script_name(english:"Foxit PDF Editor < 11.2.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Editor application (previously named Foxit PhantomPDF) installed on the remote
Windows host is prior to 11.2.5. It is, therefore affected by multiple vulnerabilities:

  - Addressed a potential issue where the application could be exposed to Use-after-Free vulnerability and
    crash, which could be exploited by attackers to execute remote code. This occurs due to the use of object
    or pointer that has been freed when executing certain JavaScripts in PDF files. (CVE-2022-43649)
    (CVE-2022-43649)

  - Addressed potential issues where the application could be exposed to Use-after-Free vulnerability and
    crash, which could be exploited by attackers to execute remote code. This occurs due to the use of object
    or pointer that has been freed when executing certain JavaScripts in PDF files. (CVE-2023-27331,
    CVE-2023-27330, CVE-2023-27329) (CVE-2023-27329, CVE-2023-27330, CVE-2023-27331)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Editor version 11.2.5 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27331");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-43649");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'FoxitPhantomPDF', win_local:TRUE);

var constraints = [
  { 'max_version' : '10.1.10.37854', 'fixed_version' : '11.2.5' },
  { 'min_version' : '11.0', 'max_version' : '11.2.4.53774', 'fixed_version' : '11.2.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
