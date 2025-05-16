#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(215059);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/13");

  script_cve_id(
    "CVE-2025-0902",
    "CVE-2025-0903",
    "CVE-2025-0904",
    "CVE-2025-0905",
    "CVE-2025-0906",
    "CVE-2025-0907",
    "CVE-2025-0908"
  );
  script_xref(name:"IAVB", value:"2025-B-0017");

  script_name(english:"PDF-XChange Editor < 10.4.2.390 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF editing application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PDF-XChange Editor installed on the remote Windows host is prior to 10.4.2.390. It is,
therefore, affected by multiple vulnerabilities, including the following:

  - A vulnerability that allows remote attackers to execute arbitrary code on affected installations of
    PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must
    visit a malicious page or open a malicious file. The specific flaw exists within the parsing of RTF
    files. The issue results from the lack of proper validation of the length of user-supplied data prior to
    copying it to a fixed-length heap-based buffer. An attacker can leverage this vulnerability to execute
    code in the context of the current process. (CVE-2025-0903)

  - A vulnerability that allows remote attackers to disclose sensitive information on affected installations
    of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target
    must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of
    XPS files. The issue results from the lack of proper validation of user-supplied data, which can result
    in a read past the end of an allocated object. An attacker can leverage this in conjunction with other
    vulnerabilities to execute arbitrary code in the context of the current process. (CVE-2025-0904)
    
  - A vulnerability that allows remote attackers to disclose sensitive information on affected installations
    of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target
    must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of
    JB2 files. The issue results from the lack of proper validation of user-supplied data, which can result
    in a read past the end of an allocated object. An attacker can leverage this in conjunction with other
    vulnerabilities to execute arbitrary code in the context of the current process. (CVE-2025-0905)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.pdf-xchange.com/support/security-bulletins.html");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-072/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-070/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-071/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-067/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-068/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-069/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-063/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PDF-XChange Editor version 10.4.2.390 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0908");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tracker-software:pdf-xchange_editor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pdf_xchange_editor_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/PDF-XChange Editor");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'PDF-XChange Editor', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '10.4.2.390' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
