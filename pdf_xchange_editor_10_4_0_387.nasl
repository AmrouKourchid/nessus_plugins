#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207517);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id(
    "CVE-2024-8812",
    "CVE-2024-8813",
    "CVE-2024-8814",
    "CVE-2024-8815",
    "CVE-2024-8816",
    "CVE-2024-8817",
    "CVE-2024-8818",
    "CVE-2024-8819",
    "CVE-2024-8820",
    "CVE-2024-8821",
    "CVE-2024-8822",
    "CVE-2024-8823",
    "CVE-2024-8824",
    "CVE-2024-8825",
    "CVE-2024-8826",
    "CVE-2024-8827",
    "CVE-2024-8828",
    "CVE-2024-8829",
    "CVE-2024-8830",
    "CVE-2024-8831",
    "CVE-2024-8832",
    "CVE-2024-8833",
    "CVE-2024-8834",
    "CVE-2024-8835",
    "CVE-2024-8836",
    "CVE-2024-8837",
    "CVE-2024-8838",
    "CVE-2024-8840",
    "CVE-2024-8841"
  );
  script_xref(name:"IAVB", value:"2024-B-0137-S");

  script_name(english:"PDF-XChange Editor < 10.4.0.387 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF editing application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PDF-XChange Editor installed on the remote Windows host is prior to 10.4.0.387. It is,
therefore, affected by multiple vulnerabilities:

  - A specific flaw exists within the parsing of XPS files. The issue results from the lack of proper validation of
    user-supplied data, which can result in a read past the end of an allocated buffer. An attacker can leverage this
    vulnerability to execute code in the context of the current process. (CVE-2024-8838)

  - A specific flaw exists within the parsing of JB2 files. The issue results from the lack of proper validation of
    user-supplied data, which can result in a read past the end of an allocated buffer. An attacker can leverage this
    vulnerability to execute code in the context of the current process. (CVE-2024-8840)

  - A specific flaw exists within the parsing of XPS files. The issue results from the lack of proper validation of
    user-supplied data, which can result in a read past the end of an allocated buffer. An attacker can leverage this
    vulnerability to execute code in the context of the current process.
    (CVE-2024-8837)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.pdf-xchange.com/support/security-bulletins.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PDF-XChange Editor version 10.4.0.387 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8840");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tracker-software:pdf-xchange_editor");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pdf_xchange_editor_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/PDF-XChange Editor");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'PDF-XChange Editor', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '10.4.0.387' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
