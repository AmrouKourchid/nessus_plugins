#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207790);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/03");

  script_cve_id(
    "CVE-2024-7725",
    "CVE-2024-9243",
    "CVE-2024-9254",
    "CVE-2024-28888"
  );
  script_xref(name:"IAVA", value:"2024-A-0593-S");

  script_name(english:"Foxit PDF Reader for Mac < 2024.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote macOS host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Reader for Mac application (previously named Foxit Reader for Mac) installed on
the remote macOS host is prior to 2024.3. It is, therefore affected by multiple vulnerabilities:

  - Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability. This vulnerability allows
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the handling of AcroForms. The issue results from the lack
    of validating the existence of an object prior to performing operations on the object. An attacker can
    leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-23928.
    (CVE-2024-7725)

  - Addressed potential issues where the application could be exposed to a Use-After-Free vulnerability and
    crash when handling certain checkbox field objects, Annotation objects, or AcroForms, which attackers
    could exploit to execute remote code or disclose information. This occurs as the application uses a wild
    pointer or an object that has been freed without proper validation, fails to properly synchronize the
    annotation items when handling the Reply Note of an annotation using JavaScript, or fails to correctly
    update the font cache after deleting a page. (CVE-2024-28888, ZDI-CAN-23932, ZDI-CAN-24135, ZDI-CAN-24489,
    ZDI-CAN-24491, ZDI-CAN-24492, ZDI-CAN-24490, ZDI-CAN-25173, ZDI-CAN-25174, ZDI-CAN-25267) (CVE-2024-28888)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Reader for Mac version 2024.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9254");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_foxit_reader_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Foxit Reader");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Foxit Reader');

var constraints = [
  { 'max_version' : '2024.2.2.64388', 'fixed_version' : '2024.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
