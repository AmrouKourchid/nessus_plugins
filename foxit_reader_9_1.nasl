#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182771);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/09");

  script_cve_id(
    "CVE-2017-14458",
    "CVE-2017-17557",
    "CVE-2018-3842",
    "CVE-2018-3843",
    "CVE-2018-3850",
    "CVE-2018-3853",
    "CVE-2018-5674",
    "CVE-2018-5675",
    "CVE-2018-5676",
    "CVE-2018-5677",
    "CVE-2018-5678",
    "CVE-2018-5679",
    "CVE-2018-5680",
    "CVE-2018-7406",
    "CVE-2018-7407",
    "CVE-2018-10302",
    "CVE-2018-10303"
  );

  script_name(english:"Foxit Reader < 9.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit Reader application installed on the remote Windows host is prior to 9.1. It is,
therefore affected by multiple vulnerabilities:

  - In Foxit Reader before 9.1 and Foxit PhantomPDF before 9.1, a flaw exists within the parsing of the
    BITMAPINFOHEADER record in BMP files. The issue results from the lack of proper validation of the biSize
    member, which can result in a heap based buffer overflow. An attacker can leverage this to execute code in
    the context of the current process. (CVE-2017-17557)

  - An exploitable use-after-free vulnerability exists in the JavaScript engine of Foxit Software's Foxit PDF
    Reader version 8.3.2.25013. A specially crafted PDF document can trigger a previously freed object in
    memory to be reused, resulting in arbitrary code execution. An attacker needs to trick the user to open
    the malicious file to trigger this vulnerability. If the browser plugin extension is enabled, visiting a
    malicious site can also trigger the vulnerability. (CVE-2017-14458)

  - An exploitable use of an uninitialized pointer vulnerability exists in the JavaScript engine in Foxit PDF
    Reader version 9.0.1.1049. A specially crafted PDF document can lead to a dereference of an uninitialized
    pointer which, if under attacker control, can result in arbitrary code execution. An attacker needs to
    trick the user to open a malicious file to trigger this vulnerability. If the browser plugin extension is
    enabled, visiting a malicious site can also trigger the vulnerability. (CVE-2018-3842)

  - An exploitable use-after-free vulnerability exists in the JavaScript engine of Foxit Software Foxit PDF
    Reader version 9.0.1.1049. A specially crafted PDF document can trigger a previously freed object in
    memory to be reused resulting in arbitrary code execution. An attacker needs to trick the user to open the
    malicious file to trigger this vulnerability. If the browser plugin extension is enabled, visiting a
    malicious site can also trigger the vulnerability. (CVE-2018-3853)

  - A use-after-free in Foxit Reader before 9.1 and PhantomPDF before 9.1 allows remote attackers to execute
    arbitrary code, aka iDefense ID V-jyb51g3mv9. (CVE-2018-10302)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/zeroday/FG-VD-18-029");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 9.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7407");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Foxit Reader', win_local:TRUE);

var constraints = [
  { 'max_version' : '9.0.1.1049', 'fixed_version' : '9.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
