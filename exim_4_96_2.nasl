#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(183510);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/23");

  script_cve_id("CVE-2023-42117", "CVE-2023-42119");

  script_name(english:"Exim < 4.96.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Exim running on the remote host is prior to 4.96.2. It is, therefore,
potentially affected by multiple vulnerabilities:

  - Improper Neutralization of Special Elements (CVE-2023-42117)

  - dnsdb Out-Of-Bounds Read (CVE-2023-42119)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://exim.org/static/doc/security/CVE-2023-zdi.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Exim 4.96.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42117");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include('compat_shared.inc');
include('smtp_func.inc');

#  Requires a non-default configuration
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var fixed_version = '4.96.2';
var port = get_service(svc:'smtp', default:25, exit_on_fail:TRUE);

var banner = get_smtp_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);
if ('Exim' >!< banner) audit(AUDIT_NOT_LISTEN, 'Exim', port);

var matches = pregmatch(pattern:"220.*Exim ([0-9\._]+)", string:banner);
if (isnull(matches)) audit(AUDIT_SERVICE_VER_FAIL, 'Exim', port);

var version = matches[1];
# Underscore was added to the vesion
version = ereg_replace(string:version, pattern:'_', replace:'.');

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  var items = {
    'Banner': banner,
    'Installed version': version,
    'Fixed version': fixed_version
  };
  var ordering = ['Banner', 'Installed version', 'Fixed version'];
  var report = report_items_str(report_items:items, ordered_fields:ordering);

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Exim', port, version);
