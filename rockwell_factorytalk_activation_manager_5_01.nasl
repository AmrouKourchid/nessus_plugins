#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189289);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/23");

  script_cve_id("CVE-2023-38545", "CVE-2023-3935");
  script_xref(name:"ICSA", value:"24-004-01");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");

  script_name(english:"Rockwell FactoryTalk Activation Manager < 5.01 RCE");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Rockwell FactoryTalk Activation Manager installed on the remote Windows host is prior to 5.01. It is, therefore, affected by a
vulnerability.

  - Rockwell Automation FactoryTalk Activation Manager and Studio 5000 Logix
    Designer uses the affected Wibu-Systems' products which internally use
    a version of libcurl that is vulnerable to a buffer overflow attack if curl
    is configured to redirect traffic through a SOCKS5 proxy. A malicious proxy
    can exploit a bug in the implemented handshake to cause a buffer overflow.
    If no SOCKS5 proxy has been configured, there is no attack surface.
    (CVE-2023-38545)

  - Rockwell Automation FactoryTalk Activation Manager and Studio 5000 Logix
    Designer uses the affected Wibu-Systems' products which contain a heap
    buffer overflow vulnerability in Wibu CodeMeter Runtime network service up
    to Version 7.60b that allows an unauthenticated, remote attacker to achieve
    RCE and gain full access of the host system. (CVE-2023-3935)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-24-004-01");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Rockwell FactoryTalk Activation Manager version 5.01 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3935");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rockwellautomation:factorytalk_activation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SCADA");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rockwell_factorytalk_activation_manager_win_installed.nbin");
  script_require_keys("installed_sw/Rockwell FactoryTalk Activation Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Rockwell FactoryTalk Activation Manager', win_local:TRUE);

var constraints = [
  {'min_version' : '4.00', 'fixed_version' : '5.01' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
