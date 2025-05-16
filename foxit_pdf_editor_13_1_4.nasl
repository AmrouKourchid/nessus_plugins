#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207793);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/03");

  script_cve_id(
    "CVE-2024-28888",
    "CVE-2024-38393",
    "CVE-2024-41605",
    "CVE-2024-48618",
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
    "CVE-2024-9256"
  );
  script_xref(name:"IAVA", value:"2024-A-0593-S");

  script_name(english:"Foxit PDF Editor < 13.1.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Editor application (previously named Foxit PhantomPDF) installed on the remote
Windows host is prior to 13.1.4. It is, therefore affected by multiple vulnerabilities:

  - A use-after-free vulnerability exists in the way Foxit Reade 2024.1.0.23997 handles a checkbox field
    object. A specially crafted Javascript code inside a malicious PDF document can trigger this
    vulnerability, which can lead to memory corruption and result in arbitrary code execution. An attacker
    needs to trick the user into opening the malicious file to trigger this vulnerability. Exploitation is
    also possible if a user visits a specially crafted, malicious site if the browser plugin extension is
    enabled. (CVE-2024-28888)

  - In Foxit PDF Reader before 2024.3, and PDF Editor before 2024.3 and 13.x before 13.1.4, an attacker can
    replace an update file with a Trojan horse via side loading, because the update service lacks integrity
    validation for the updater. Attacker-controlled code may thus be executed. (CVE-2024-41605)

  - This type of vulnerability occurs when a program continues to use a pointer to memory after it has been
    freed, which can lead to various security issues. The vulnerability is likely triggered by manipulating
    checkbox operations in the affected application, which could potentially an attacker to cause denial of
    service (DoS) by repeatedly triggering the crash and leveraging the crash to gain unauthorized access or
    execute malicious code. (CVE-2024-9243)

  - Addressed potential issues where the application could be exposed to a Use-After-Free vulnerability and
    crash when handling certain checkbox field objects, Doc objects, Annotation objects, or AcroForms, which
    attackers could exploit to execute remote code or disclose information. This occurs as the application
    uses a wild pointer or an object that has been freed without proper validation, fails to properly
    synchronize the annotation items when handling the Reply Note of an annotation using JavaScript, or fails
    to correctly update the font cache after deleting a page. (CVE-2024-28888, CVE-2024-7722, CVE-2024-7723,
    CVE-2024-7724, CVE-2024-7725, CVE-2024-9243, CVE-2024-9246, CVE-2024-9250, CVE-2024-9252, CVE-2024-9253,
    CVE-2024-9251, CVE-2024-9254, CVE-2024-9255, CVE-2024-9256) (CVE-2024-9246, CVE-2024-9252)

  - The vulnerability could cause the application to crash when parsing certain PDF files, potentially leading
    to denial of service (DoS) attacks. (CVE-2024-9250)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Editor version 13.1.4 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9254");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'FoxitPhantomPDF', win_local:TRUE);

var constraints = [
  { 'max_version' : '11.2.10.53951', 'fixed_version' : '13.1.4' },
  { 'min_version' : '12.0', 'max_version' : '12.1.7.15526', 'fixed_version' : '13.1.4' },
  { 'min_version' : '13.0', 'max_version' : '13.1.3.22478', 'fixed_version' : '13.1.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
