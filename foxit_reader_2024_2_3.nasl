#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207699);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id(
    "CVE-2024-7722",
    "CVE-2024-7723",
    "CVE-2024-7724",
    "CVE-2024-7725"
  );

  script_name(english:"Foxit PDF Reader < 2024.2.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Reader application (previously named Foxit PhantomPDF) installed on the remote
Windows host is prior to 2024.2.3. It is, therefore affected by multiple vulnerabilities:

  - Foxit PDF Reader Doc Object Use-After-Free Information Disclosure Vulnerability. This vulnerability 
    allows remote attackers to disclose sensitive information on affected installations of Foxit PDF Reader. 
    User interaction is required to exploit this vulnerability in that the target must visit a malicious 
    page or open a malicious file. The specific flaw exists within the handling of Doc objects. The issue 
    results from the lack of validating the existence of an object prior to performing operations on the 
    object. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary 
    code in the context of the current process. (CVE-2024-7722)

  - Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability. This vulnerability allows 
    remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader. User 
    interaction is required to exploit this vulnerability in that the target must visit a malicious page or 
    open a malicious file. The specific flaw exists within the handling of AcroForms. The issue results from 
    the lack of validating the existence of an object prior to performing operations on the object. An 
    attacker can leverage this vulnerability to execute code in the context of the current process. 
    (CVE-2024-7723, CVE-2024-7724, CVE-2024-7725)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Reader version 2024.2.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7725");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
  { 'max_version' : '2024.2.2.25170', 'fixed_version' : '2024.2.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
