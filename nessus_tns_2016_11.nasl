#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92465);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/12");

  script_cve_id("CVE-2016-0718", "CVE-2016-1000028", "CVE-2016-1000029");
  script_bugtraq_id(90729);

  script_name(english:"Tenable Nessus 6.x < 6.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Tenable Nessus
application running on the remote host is 6.x prior to 6.8. It is,
therefore, affected by multiple vulnerabilities :

  - A buffer overflow condition exists in the Expat XML
    parser due to improper validation of user-supplied input
    when handling malformed input documents. An
    authenticated, remote attacker can exploit this to cause
    a denial of service condition or the execution of
    arbitrary code. (CVE-2016-0718)

  - A stored cross-site (XSS) scripting vulnerability exists
    that can be exploited by an authenticated, remote
    attacker that has user-level access to the Nessus user
    interface. (CVE-2016-1000028)

  - Multiple stored cross-site (XSS) scripting
    vulnerabilities exist that can be exploited by an
    authenticated, remote attacker that has
    administrative-level access to the Nessus user
    interface. These issues would only affect other users
    with administrative access. (CVE-2016-1000029)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2016-11");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus version 6.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0718");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libexpat:expat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_detect.nasl", "nessus_installed_win.nbin", "nessus_installed_linux.nbin", "macos_nessus_installed.nbin");
	script_require_keys("installed_sw/Tenable Nessus");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Tenable Nessus');

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.8.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);