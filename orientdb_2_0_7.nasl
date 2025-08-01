#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86315);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2015-2913");
  script_bugtraq_id(76610);
  script_xref(name:"CERT", value:"845332");

  script_name(english:"OrientDB < 2.0.7 / 2.1.0 Weak Session IDs");
  script_summary(english:"Checks the version of OrientDB.");

  script_set_attribute(attribute:"synopsis", value:
"The version of OrientDB running on the remote host uses weak session
IDs.");
  script_set_attribute(attribute:"description", value:
"The version of OrientDB running on the remote host is prior to 2.0.7
or 2.1.0. It is, therefore, affected by a weak session ID flaw due to
usage of the Java library java.util.Random. An unauthenticated, remote
attacker can exploit this to predict session IDs to facilitate
brute-force attacks. Some sources report that versions prior to 2.1.0
are vulnerable. Tenable research has confirmed that the fix was
included in all official releases of OrientDB beginning with version
2.0.7 and version 2.1-rc3 by inspecting the source of these releases.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OrientDB version 2.0.7 / 2.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2913");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:orientdb:orientdb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("orientdb_detect.nbin");
  script_require_keys("installed_sw/OrientDB");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http_func.inc");

app_name = "OrientDB";
get_install_count(app_name:app_name, exit_if_zero:TRUE); # Stops port branching

port    = get_http_port(default:2480, embedded:TRUE);
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
url     = build_url2(qs:install['path'],port:port);
fix     = FALSE;
prver   = install['Pre-release'];

# All 2.0 release candidates affected
if(ver =~ "^2\.0$" && !isnull(prver))
  fix = "2.0.7 / 2.1.0";
# Confirmed RC1/RC2 are missing the fixes
else if(ver =~ "^2\.1$" && prver =~ "^rc[1-2]$")
  fix = "2.1.0";
# Everything below 2.0.7 is affected
else if(ver_compare(fix:"2.0.7", ver:version, strict:FALSE) < 0)
  fix = "2.0.7 / 2.1.0";

if(fix)
{
  if(prver)
    version = version + "-" + prver;
  if (report_verbosity > 0)
  {
    report = '\n  Path              : '+url+
             '\n  Installed version : '+version+
             '\n  Fixed version     : '+fix+
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url);
