#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187164);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id("CVE-2023-39340", "CVE-2023-41719", "CVE-2023-41720");

  script_name(english:"Ivanti Connect Secure 9.1Rx < 9.1R18.5 / 22.x < 22.4R1.1 / 22.5Rx < 22.5R2.3 / 22.6Rx < 22.6R2.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A VPN solution installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Ivanti Connect Secure installed on the remote host is 9.1Rx prior to 9.1R18.5, 22.x prior to 22.4R1.1, 22.5Rx prior
to 22.5R2.3, or 22.6Rx < 22.6R2.2. It is, therefore, affected by  multiple vulnerabilities. 

  - A vulnerability exists on both branches of Ivanti Connect Secure (9.1Rx and 22x) below 22.6R2 or 9.1R18.2
    where an attacker can send a specific request which may lead to Denial of Service (DoS) of the appliance.
    (DoS) of the appliance. NOTE: (There are patch versions listed in the resolution section below 22.6R2 that
    contain the patch) (CVE-2023-39340)

  - A vulnerability exists on both branches of Ivanti Connect Secure (9.1Rx and 22x) below 22.6R2 or 9.1R18.5
    where an attacker impersonating an administrator may craft a specific web request which may lead to remote
    code execution. NOTE: (There are patch versions listed in the resolution section below 22.6R2 that contain
    the patch) (CVE-2023-41719)

  - A vulnerability exists on the 22x branch of Ivanti Connect Secure below 22.6R2 where an attacker can
    escalate their privileges by exploiting a vulnerable installed application. This vulnerability allows the
    attacker to gain elevated execution privileges on the affected system. NOTE: (There are patch versions
    listed in the resolution section below 22.6R2 that contain the patch) (CVE-2023-41720)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://forums.ivanti.com/s/article/Security-patch-release-Ivanti-Connect-Secure-22-6R2-and-22-6R2-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4160ef92");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ivanti Secure Desktop Client 9.1R18.5, 22.4R1.1, 22.5R2.3, 22.6R2.2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41719");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-41720");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_secure_desktop_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include('vcf_extras.inc');

var port = get_http_port(default:443, embedded:TRUE);
var app_info = vcf::pulse_connect_secure::get_app_info(app:'Pulse Connect Secure', port:port, full_version:TRUE, webapp:TRUE);

var constraints = [
  {'min_version':'9.1',  'fixed_version':'9.1.18.25187',  'fixed_display':'9.1R18.5 (Build 25187)'},
  {'min_version':'22.0', 'fixed_version':'22.4.1.2165',   'fixed_display':'22.4R1.1 (Build 2165)'},
  {'min_version':'22.5', 'fixed_version':'22.5.2.2215',   'fixed_display':'22.5R2.3 (Build 2215)'},
  {'min_version':'22.6', 'fixed_version':'22.6.2.2677',   'fixed_display':'22.6R2.2 (Build 2677)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
