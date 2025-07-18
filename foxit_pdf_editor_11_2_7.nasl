#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182080);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/05");

  script_cve_id(
    "CVE-2023-27379",
    "CVE-2023-28744",
    "CVE-2023-32664",
    "CVE-2023-33866",
    "CVE-2023-33876",
    "CVE-2023-38105",
    "CVE-2023-38106",
    "CVE-2023-38107",
    "CVE-2023-38108",
    "CVE-2023-38109",
    "CVE-2023-38110",
    "CVE-2023-38111",
    "CVE-2023-38112",
    "CVE-2023-38113",
    "CVE-2023-38114",
    "CVE-2023-38115",
    "CVE-2023-38116",
    "CVE-2023-38117",
    "CVE-2023-38118",
    "CVE-2023-38119"
  );

  script_name(english:"Foxit PDF Editor < 11.2.7 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Editor application (previously named Foxit PhantomPDF) installed on the remote
Windows host is prior to 11.2.7. It is, therefore affected by multiple vulnerabilities:

  - A use-after-free vulnerability exists in the JavaScript engine of Foxit Software's PDF Reader, version
    12.1.2.15332. By prematurely deleting objects associated with pages, a specially crafted PDF document can
    trigger the reuse of previously freed memory, which can lead to arbitrary code execution. An attacker
    needs to trick the user into opening the malicious file to trigger this vulnerability. Exploitation is
    also possible if a user visits a specially crafted, malicious site if the browser plugin extension is
    enabled. (CVE-2023-27379, CVE-2023-33866)

  - A use-after-free vulnerability exists in the JavaScript engine of Foxit Software's PDF Reader, version
    12.1.1.15289. A specially crafted PDF document can trigger the reuse of previously freed memory by
    manipulating form fields of a specific type. This can lead to memory corruption and arbitrary code
    execution. An attacker needs to trick the user into opening the malicious file to trigger this
    vulnerability. Exploitation is also possible if a user visits a specially crafted, malicious site if the
    browser plugin extension is enabled. (CVE-2023-28744)

  - A type confusion vulnerability exists in the Javascript checkThisBox method as implemented in Foxit Reader
    12.1.2.15332. Specially crafted Javascript code inside a malicious PDF document can cause memory
    corruption and lead to remote code execution. User would need to open a malicious file to trigger the
    vulnerability. (CVE-2023-32664)

  - A use-after-free vulnerability exists in the way Foxit Reader 12.1.2.15332 handles destroying annotations.
    Specially crafted Javascript code inside a malicious PDF document can trigger reuse of a previously freed
    object, which can lead to memory corruption and result in arbitrary code execution. An attacker needs to
    trick the user into opening the malicious file to trigger this vulnerability. Exploitation is also
    possible if a user visits a specially crafted, malicious site if the browser plugin extension is enabled.
    (CVE-2023-33876)

  - Addressed potential issues where the application could be exposed to Use-after-Free or Out-of-Bounds Read
    vulnerability and crash, which could be exploited by attackers to execute remote code or disclose
    information. This occurs due to the access of null pointer/wild pointer or reference to the object that
    has been deleted without proper validation when handling certain JavaScripts. (CVE-2023-28744,
    CVE-2023-38111, CVE-2023-38107, CVE-2023-38109, CVE-2023-38113, CVE-2023-38112, CVE-2023-38110,
    CVE-2023-38117) (CVE-2023-38107, CVE-2023-38109, CVE-2023-38110, CVE-2023-38111, CVE-2023-38112,
    CVE-2023-38113, CVE-2023-38117)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Editor version 11.2.7 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-33876");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'FoxitPhantomPDF', win_local:TRUE);

var constraints = [
  { 'max_version' : '10.1.12.37872', 'fixed_version' : '11.2.7' },
  { 'min_version' : '11.0', 'max_version' : '11.2.6.53790', 'fixed_version' : '11.2.7' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
