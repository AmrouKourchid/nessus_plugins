#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187209);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/25");

  script_cve_id(
    "CVE-2023-6364",
    "CVE-2023-6365",
    "CVE-2023-6366",
    "CVE-2023-6367",
    "CVE-2023-6368",
    "CVE-2023-6595"
  );

  script_name(english:"Progress WhatsUp Gold < 23.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Progress WhatsUp Gold application installed on the remote host is
prior to 23.1. It is, therefore, affected by multiple vulnerabilities:

  - In WhatsUp Gold versions released before 2023.1, a stored cross-site scripting (XSS) vulnerability has been 
    identified. It is possible for an attacker to craft a XSS payload and store that value within a dashboard component.   
    If a WhatsUp Gold user interacts with the crafted payload, the attacker would be able to execute malicious 
    JavaScript within the context of the victims browser. (CVE-2023-6364)

  - In WhatsUp Gold versions released before 2023.1, an API endpoint was found to be missing an authentication 
    mechanism. It is possible for an unauthenticated attacker to enumerate information related to a registered device 
    being monitored by WhatsUp Gold. (CVE-2023-6368)

  - In WhatsUp Gold versions released before 2023.1, an API endpoint was found to be missing an authentication 
    mechanism. It is possible for an unauthenticated attacker to enumerate ancillary credential information stored 
    within WhatsUp Gold. (CVE-2023-6595)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/WhatsUp-Gold-Security-Bulletin-December-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e277c2ec");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ipswitch WhatsUp Gold version 23.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6367");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:whatsup_gold");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:whatsup_gold");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ipswitch_whatsup_gold_installed.nasl");
  script_require_keys("installed_sw/Ipswitch WhatsUp Gold");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Ipswitch WhatsUp Gold');

var constraints = [ {'fixed_version': '23.1.0'} ];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
