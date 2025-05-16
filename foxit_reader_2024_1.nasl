#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191535);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/20");

  script_cve_id(
    "CVE-2024-25858",
    "CVE-2024-30322",
    "CVE-2024-30323",
    "CVE-2024-30324",
    "CVE-2024-30325",
    "CVE-2024-30326",
    "CVE-2024-30327",
    "CVE-2024-30328",
    "CVE-2024-30329",
    "CVE-2024-30330",
    "CVE-2024-30331",
    "CVE-2024-30332",
    "CVE-2024-30333",
    "CVE-2024-30334",
    "CVE-2024-30335",
    "CVE-2024-30336",
    "CVE-2024-30337",
    "CVE-2024-30338",
    "CVE-2024-30339",
    "CVE-2024-30340",
    "CVE-2024-30341",
    "CVE-2024-30342",
    "CVE-2024-30343",
    "CVE-2024-30344",
    "CVE-2024-30345",
    "CVE-2024-30346",
    "CVE-2024-30347",
    "CVE-2024-30348",
    "CVE-2024-30349",
    "CVE-2024-30350",
    "CVE-2024-30351",
    "CVE-2024-30352",
    "CVE-2024-30353",
    "CVE-2024-30354",
    "CVE-2024-30355",
    "CVE-2024-30356",
    "CVE-2024-30357",
    "CVE-2024-30358",
    "CVE-2024-30359",
    "CVE-2024-30360",
    "CVE-2024-30361",
    "CVE-2024-30362",
    "CVE-2024-30363",
    "CVE-2024-30364",
    "CVE-2024-30365",
    "CVE-2024-30366",
    "CVE-2024-30367",
    "CVE-2024-30371",
    "CVE-2024-32488"
  );
  script_xref(name:"IAVA", value:"2024-A-0137-S");

  script_name(english:"Foxit PDF Reader < 2024.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Reader application (previously named Foxit Reader) installed on the remote
Windows host is prior to 2024.1. It is, therefore affected by multiple vulnerabilities:

  - In Foxit PDF Reader before 2024.1 and PDF Editor before 2024.1, code execution via JavaScript could occur
    because of an unoptimized prompt message for users to review parameters of commands. (CVE-2024-25858)

  - Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability. This vulnerability allows
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the handling of AcroForms. The issue results from the lack
    of validating the existence of an object prior to performing operations on the object. An attacker can
    leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-22499.
    (CVE-2024-30322)

  - Foxit PDF Reader Doc Object Use-After-Free Remote Code Execution Vulnerability. This vulnerability allows
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the handling of Doc objects. The issue results from the
    lack of validating the existence of an object prior to performing operations on the object. An attacker
    can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-22576.
    (CVE-2024-30324)

  - Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability. This vulnerability allows
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the handling of Doc objects in AcroForms. The issue
    results from the lack of validating the existence of an object prior to performing operations on the
    object. An attacker can leverage this vulnerability to execute code in the context of the current process.
    Was ZDI-CAN-22592. (CVE-2024-30325)

  - Foxit PDF Reader Doc Object Use-After-Free Remote Code Execution Vulnerability. This vulnerability allows
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the handling of Doc objects. The issue results from the
    lack of validating the existence of an object prior to performing operations on the object. An attacker
    can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-22593.
    (CVE-2024-30326)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Reader version 2024.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30359");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-25858");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Foxit Reader', win_local:TRUE);

var constraints = [
  { 'max_version' : '2023.3.0.23028', 'fixed_version' : '2024.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
