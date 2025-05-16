#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189275);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/22");

  script_cve_id(
    "CVE-2023-32616",
    "CVE-2023-35985",
    "CVE-2023-38573",
    "CVE-2023-39542",
    "CVE-2023-40194",
    "CVE-2023-41257",
    "CVE-2023-42089",
    "CVE-2023-42090",
    "CVE-2023-42091",
    "CVE-2023-42092",
    "CVE-2023-42093",
    "CVE-2023-42094",
    "CVE-2023-42095",
    "CVE-2023-42096",
    "CVE-2023-42097",
    "CVE-2023-42098",
    "CVE-2023-51549",
    "CVE-2023-51550",
    "CVE-2023-51551",
    "CVE-2023-51552",
    "CVE-2023-51553",
    "CVE-2023-51554",
    "CVE-2023-51555",
    "CVE-2023-51556",
    "CVE-2023-51557",
    "CVE-2023-51558",
    "CVE-2023-51559",
    "CVE-2023-51560",
    "CVE-2023-51562"
  );

  script_name(english:"Foxit PDF Editor < 11.2.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Editor application (previously named Foxit PhantomPDF) installed on the remote
Windows host is prior to 11.2.8. It is, therefore affected by multiple vulnerabilities:

  - A use-after-free vulnerability exists in the way Foxit Reader 12.1.2.15356 handles 3D annotations. A
    specially crafted Javascript code inside a malicious PDF document can trigger reuse of a previously freed
    object, which can lead to memory corruption and result in arbitrary code execution. An attacker needs to
    trick the user into opening the malicious file to trigger this vulnerability. Exploitation is also
    possible if a user visits a specially crafted, malicious site if the browser plugin extension is enabled.
    (CVE-2023-32616)

  - A use-after-free vulnerability exists in the way Foxit Reader 12.1.2.15356 handles a signature field. A
    specially crafted Javascript code inside a malicious PDF document can trigger reuse of a previously freed
    object, which can lead to memory corruption and result in arbitrary code execution. An attacker needs to
    trick the user into opening the malicious file to trigger this vulnerability. Exploitation is also
    possible if a user visits a specially crafted, malicious site if the browser plugin extension is enabled.
    (CVE-2023-38573)

  - A type confusion vulnerability exists in the way Foxit Reader 12.1.2.15356 handles field value properties.
    A specially crafted Javascript code inside a malicious PDF document can trigger this vulnerability, which
    can lead to memory corruption and result in arbitrary code execution. An attacker needs to trick the user
    into opening the malicious file to trigger this vulnerability. Exploitation is also possible if a user
    visits a specially crafted, malicious site if the browser plugin extension is enabled. (CVE-2023-41257)

  - An arbitrary file creation vulnerability exists in the Javascript exportDataObject API of Foxit Reader
    12.1.3.15356 due to a failure to properly validate a dangerous extension. A specially crafted malicious
    file can create files at arbitrary locations, which can lead to arbitrary code execution. An attacker
    needs to trick the user into opening the malicious file to trigger this vulnerability. Exploitation is
    also possible if a user visits a specially-crafted malicious site if the browser plugin extension is
    enabled. (CVE-2023-35985)

  - An arbitrary file creation vulnerability exists in the Javascript exportDataObject API of Foxit Reader
    12.1.3.15356 due to mistreatment of whitespace characters. A specially crafted malicious file can create
    files at arbitrary locations, which can lead to arbitrary code execution. An attacker needs to trick the
    user into opening the malicious file to trigger this vulnerability. Exploitation is also possible if a
    user visits a specially crafted, malicious site if the browser plugin extension is enabled.
    (CVE-2023-40194)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Editor version 11.2.8 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41257");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/22");

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
  { 'max_version' : '10.1.12.37872', 'fixed_version' : '11.2.8' },
  { 'min_version' : '11.0', 'max_version' : '11.2.7.53812', 'fixed_version' : '11.2.8' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
