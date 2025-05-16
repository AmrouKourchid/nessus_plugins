#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207903);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/02");

  script_cve_id(
    "CVE-2024-7722",
    "CVE-2024-7723",
    "CVE-2024-7724",
    "CVE-2024-7725",
    "CVE-2024-9243",
    "CVE-2024-9244",
    "CVE-2024-9245",
    "CVE-2024-9246",
    "CVE-2024-9247",
    "CVE-2024-9248",
    "CVE-2024-9249",
    "CVE-2024-9250",
    "CVE-2024-9251",
    "CVE-2024-9252",
    "CVE-2024-9253",
    "CVE-2024-9254",
    "CVE-2024-9255",
    "CVE-2024-9256",
    "CVE-2024-28888",
    "CVE-2024-38393",
    "CVE-2024-41605",
    "CVE-2024-48618"
  );

  script_name(english:"Foxit PDF Editor < 12.1.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Editor application (previously named Foxit PhantomPDF) installed on the remote
Windows host is prior to 12.1.8. It is, therefore affected by multiple vulnerabilities:

  - A use-after-free vulnerability exists in the way Foxit Reade 2024.1.0.23997 handles a checkbox field
    object. A specially crafted Javascript code inside a malicious PDF document can trigger this
    vulnerability, which can lead to memory corruption and result in arbitrary code execution. An attacker
    needs to trick the user into opening the malicious file to trigger this vulnerability. Exploitation is
    also possible if a user visits a specially crafted, malicious site if the browser plugin extension is
    enabled. (CVE-2024-28888)

  - Foxit PDF Reader Doc Object Use-After-Free Information Disclosure Vulnerability. This vulnerability allows
    remote attackers to disclose sensitive information on affected installations of Foxit PDF Reader. User
    interaction is required to exploit this vulnerability in that the target must visit a malicious page or
    open a malicious file. The specific flaw exists within the handling of Doc objects. The issue results from
    the lack of validating the existence of an object prior to performing operations on the object. An
    attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the
    context of the current process. Was ZDI-CAN-23702. (CVE-2024-7722)

  - Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability. This vulnerability allows
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the handling of AcroForms. The issue results from the lack
    of validating the existence of an object prior to performing operations on the object. An attacker can
    leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-23736.
    (CVE-2024-7723)

  - Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability. This vulnerability allows
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the handling of AcroForms. The issue results from the lack
    of validating the existence of an object prior to performing operations on the object. An attacker can
    leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-23900.
    (CVE-2024-7724)

  - Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability. This vulnerability allows
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the handling of AcroForms. The issue results from the lack
    of validating the existence of an object prior to performing operations on the object. An attacker can
    leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-23928.
    (CVE-2024-7725)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Editor version 12.1.8 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9254");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'FoxitPhantomPDF', win_local:TRUE);

var constraints = [
  { 'max_version' : '11.2.10.53951', 'fixed_version' : '12.1.8' },
  { 'min_version' : '12.0', 'max_version' : '12.1.7.15526', 'fixed_version' : '12.1.8' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
