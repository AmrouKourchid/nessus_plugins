#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213089);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/31");

  script_cve_id(
    "CVE-2024-12751",
    "CVE-2024-12752",
    "CVE-2024-12753",
    "CVE-2024-47810",
    "CVE-2024-49576"
  );
  script_xref(name:"IAVA", value:"2024-A-0829");

  script_name(english:"Foxit PDF Editor < 13.1.5 / 2024.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Editor application (previously named Foxit PhantomPDF) installed on the remote
Windows host is prior to 2024.4/13.1.5. It is, therefore affected by multiple vulnerabilities:

  - A use-after-free vulnerability exists in the way Foxit Reader 2024.3.0.26795 handles a checkbox CBF_Widget
    object. A specially crafted Javascript code inside a malicious PDF document can trigger this
    vulnerability, which can lead to memory corruption and result in arbitrary code execution. An attacker
    needs to trick the user into opening the malicious file to trigger this vulnerability. Exploitation is
    also possible if a user visits a specially crafted, malicious site if the browser plugin extension is
    enabled. (CVE-2024-49576)

  - Foxit PDF Reader AcroForm Out-Of-Bounds Read Remote Code Execution Vulnerability. This vulnerability
    allows remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User
    interaction is required to exploit this vulnerability in that the target must visit a malicious page or
    open a malicious file. The specific flaw exists within the handling of AcroForms. The issue results from
    the lack of proper validation of user-supplied data, which can result in a read past the end of an
    allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the
    current process. Was ZDI-CAN-25344. (CVE-2024-12751)

  - Foxit PDF Reader AcroForm Memory Corruption Remote Code Execution Vulnerability. This vulnerability allows
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User interaction
    is required to exploit this vulnerability in that the target must visit a malicious page or open a
    malicious file. The specific flaw exists within the handling of AcroForms. The issue results from the lack
    of proper validation of user-supplied data, which can result in a memory corruption condition. An attacker
    can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-25345.
    (CVE-2024-12752)

  - A use-after-free vulnerability exists in the way Foxit Reader 2024.3.0.26795 handles a 3D page object. A
    specially crafted Javascript code inside a malicious PDF document can trigger this vulnerability, which
    can lead to memory corruption and result in arbitrary code execution. An attacker needs to trick the user
    into opening the malicious file to trigger this vulnerability. Exploitation is also possible if a user
    visits a specially crafted, malicious site if the browser plugin extension is enabled. (CVE-2024-47810)

  - Foxit PDF Reader Link Following Local Privilege Escalation Vulnerability. This vulnerability allows local
    attackers to escalate privileges on affected installations of Foxit PDF Reader. An attacker must first
    obtain the ability to execute low-privileged code on the target system in order to exploit this
    vulnerability. The specific flaw exists within the product installer. By creating a junction, an attacker
    can abuse the installer process to create an arbitrary file. An attacker can leverage this vulnerability
    to escalate privileges and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-25408.
    (CVE-2024-12753)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Editor version 13.1.5 / 2024.4 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49576");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'max_version' : '11.2.11.54113', 'fixed_version' : '13.1.5', 'fixed_display' : '2024.4/13.1.5' },
  { 'min_version' : '12.0', 'max_version' : '12.1.8.15703', 'fixed_version' : '13.1.5', 'fixed_display' : '2024.4/13.1.5' },
  { 'min_version' : '13.0', 'max_version' : '13.1.4.23147', 'fixed_version' : '13.1.5', 'fixed_display' : '2024.4/13.1.5' },
  { 'min_version' : '2023.0', 'max_version' : '2023.3.0.23028', 'fixed_version' : '2024.4' },
  { 'min_version' : '2024.0', 'max_version' : '2024.3.0.26795', 'fixed_version' : '2024.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
