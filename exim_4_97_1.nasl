#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187639);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/19");

  script_cve_id("CVE-2023-51766");
  script_xref(name:"IAVA", value:"2024-A-0002-S");

  script_name(english:"Exim < 4.97.1 SMTP smuggling");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is potentially affected by a SMTP smuggling vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Exim before 4.97.1 allows SMTP smuggling in certain PIPELINING/CHUNKING configurations. Remote attackers can use a
published exploitation technique to inject e-mail messages with a spoofed MAIL FROM address, allowing bypass of an
SPF protection mechanism. This occurs because Exim supports <LF>.<CR><LF> but some other popular e-mail servers do not.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/Exim/exim/blob/master/doc/doc-txt/cve-2023-51766
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab90db8b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Exim 4.97.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-51766");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include('compat_shared.inc');
include('smtp_func.inc');

#  Requires a non-default configuration
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var fixed_version = '4.97.1';
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

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Exim', port, version);
