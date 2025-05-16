#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194423);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2024-25575",
    "CVE-2024-25648",
    "CVE-2024-25938",
    "CVE-2024-30324",
    "CVE-2024-30327",
    "CVE-2024-30328",
    "CVE-2024-30331",
    "CVE-2024-30336",
    "CVE-2024-30342",
    "CVE-2024-30343",
    "CVE-2024-30344",
    "CVE-2024-30345",
    "CVE-2024-30346",
    "CVE-2024-30348",
    "CVE-2024-30351",
    "CVE-2024-30354",
    "CVE-2024-30357",
    "CVE-2024-30361",
    "CVE-2024-30362",
    "CVE-2024-30363",
    "CVE-2024-30365",
    "CVE-2024-30366"
  );
  script_xref(name:"IAVA", value:"2024-A-0266-S");

  script_name(english:"Foxit PDF Editor for Mac < 11.1.7 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote macOS host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Editor for Mac application (previously named Foxit PhantomPDF for Mac) installed
on the remote macOS host is prior to 11.1.7. It is, therefore affected by multiple vulnerabilities:

  - Foxit PDF Reader Doc Object Use-After-Free Remote Code Execution Vulnerability. This vulnerability allows
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the handling of Doc objects. The issue results from the
    lack of validating the existence of an object prior to performing operations on the object. An attacker
    can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-22576.
    (CVE-2024-30324)

  - Foxit PDF Reader template Use-After-Free Remote Code Execution Vulnerability. This vulnerability allows
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the handling of template objects. The issue results from
    the lack of validating the existence of an object prior to performing operations on the object. An
    attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-
    CAN-22632. (CVE-2024-30327)

  - Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability. This vulnerability allows
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the handling of Doc objects in AcroForms. The issue
    results from the lack of validating the existence of an object prior to performing operations on the
    object. An attacker can leverage this vulnerability to execute code in the context of the current process.
    Was ZDI-CAN-22633. (CVE-2024-30328)

  - Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability. This vulnerability allows
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the handling of Doc objects in AcroForms. The issue
    results from the lack of validating the existence of an object prior to performing operations on the
    object. An attacker can leverage this vulnerability to execute code in the context of the current process.
    Was ZDI-CAN-22637. (CVE-2024-30331)

  - Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability. This vulnerability allows
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the handling of Doc objects in AcroForms. The issue
    results from the lack of validating the existence of an object prior to performing operations on the
    object. An attacker can leverage this vulnerability to execute code in the context of the current process.
    Was ZDI-CAN-22642. (CVE-2024-30336)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Editor for Mac version 11.1.7 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-25938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_foxit_phantompdf_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Foxit PhantomPDF");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Foxit PhantomPDF');

var constraints = [
  { 'max_version' : '11.1.6.0109', 'fixed_version' : '11.1.7' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
