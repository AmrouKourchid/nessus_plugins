#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197733);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/14");

  script_cve_id("CVE-2014-100005");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/06");

  script_name(english:"DLink DIR < 2.17.b02 (SAP10018)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of DLink DIR installed on the remote host is prior to 2.17.b02. It is, therefore, affected by a
vulnerability as referenced in the SAP10018 advisory.

  - Multiple cross-site request forgery (CSRF) vulnerabilities in D-Link DIR-600 router (rev. Bx) with
    firmware before 2.17b02 allow remote attackers to hijack the authentication of administrators for requests
    that (1) create an administrator account or (2) enable remote management via a crafted configuration
    module to hedwig.cgi, (3) activate new configuration settings via a SETCFG,SAVE,ACTIVATE action to
    pigwidgeon.cgi, or (4) send a ping via a ping action to diagnostic.php. (CVE-2014-100005)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1b36019");
  script_set_attribute(attribute:"solution", value:
"Upgrade DLink DIR based upon the guidance specified in SAP10018.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-100005");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'D-Link DIR-645 / DIR-815 diagnostic.php Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:d-link:dir-600");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dlink_dir_www_detect.nbin");
  script_require_keys("installed_sw/DLink DIR");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80, embedded:TRUE);

var app_info = vcf::get_app_info(app:'DLink DIR', port:port, webapp:TRUE);

if (empty_or_null(app_info['model']) ||
    'DIR-600' >!< app_info['model'])
    audit(AUDIT_DEVICE_NOT_VULN, 'DLink DIR model');

var constraints = [
  { 'max_version' : '2.16ww', 'fixed_version' : '2.17.b02' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xsrf':TRUE}
);
