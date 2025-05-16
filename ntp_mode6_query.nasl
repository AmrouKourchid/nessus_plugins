#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97861);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/12");

  script_name(english:"Network Time Protocol (NTP) Mode 6 Scanner");
  script_summary(english:"NTP responds to mode 6 queries.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server responds to mode 6 queries.");
  script_set_attribute(attribute:"description", value:
"The remote NTP server responds to mode 6 queries. Devices that respond
to these queries have the potential to be used in NTP amplification
attacks. An unauthenticated, remote attacker could potentially exploit
this, via a specially crafted mode 6 query, to cause a reflected
denial of service condition.");
  # https://web.archive.org/web/20190130062446/https://ntpscan.shadowserver.org/
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?18e62de1");
  script_set_attribute(attribute:"see_also", value:"https://www.virtuesecurity.com/kb/ntp-mode-6-vulnerabilities/");
  script_set_attribute(attribute:"solution", value:
 "Restrict NTP mode 6 queries.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:'cvss_score_rationale', value:"Score based on an in-depth analysis by Tenable.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ntp_open.nasl");
  script_require_keys("Services/udp/ntp");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"ntp", default:123);
res = get_kb_item("NTP/mode6_response");
limited = get_kb_item('NTP/mode6_response_ratelimit');

if (empty_or_null(res)) exit(0, "Host does not respond to NTP Mode 6 queries.");
if (limited) exit(0, "The host rate-limits NTP Mode 6 queries, mitigating DoS conditions.");
report = '\n  Nessus elicited the following response from the remote' +
         '\n  host by sending an NTP mode 6 query :' +
         '\n\n\'' + res + '\'';
security_report_v4(port:port, proto:"udp", extra:report, severity:SECURITY_WARNING);
