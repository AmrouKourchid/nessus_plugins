#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211396);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/18");

  script_cve_id("CVE-2024-20533", "CVE-2024-20534");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm38104");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm39676");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41649");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41650");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41651");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41656");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41657");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41664");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41666");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41668");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41710");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41711");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41712");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41715");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41716");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41721");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41723");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm41724");
  script_xref(name:"CISCO-SA", value:"cisco-sa-mpp-xss-8tAV2TvF");
  script_xref(name:"IAVA", value:"2024-A-0720");

  script_name(english:"Cisco IP Phones Stored XSS (cisco-sa-mpp-xss-8tAV2TvF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco 6800, 7800, 8800, and 9800 Series Phones with Multiplatform Firmware
Stored Cross-Site Scripting Vulnerabilities is affected by multiple vulnerabilities.

  - A vulnerability in the web UI of Cisco Desk Phone 9800 Series, Cisco IP Phone 6800, 7800, and 8800 Series,
    and Cisco Video Phone 8875 with Cisco Multiplatform Firmware could allow an authenticated, remote attacker
    to conduct stored cross-site scripting (XSS) attacks against users. This vulnerability exists because the
    web UI of an affected device does not properly validate user-supplied input. An attacker could exploit
    this vulnerability by injecting malicious code into specific pages of the interface. A successful exploit
    could allow the attacker to execute arbitrary script code in the context of the affected interface or
    access sensitive, browser-based information. Note: To exploit this vulnerability, Web Access must be
    enabled on the phone and the attacker must have Admin credentials on the device. Web Access is disabled by
    default. (CVE-2024-20533, CVE-2024-20534)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-mpp-xss-8tAV2TvF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b42ac96");
  script_set_attribute(attribute:"solution", value:
"Apply the fix referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20533");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-20534");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:ip_phone");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:ip_phone");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ip_phone_sip_detect.nbin");
  script_require_keys("installed_sw/Cisco IP Phone", "Settings/ParanoidReport");
  script_require_ports("Services/sip", "Services/udp/sip");

  exit(0);
}

include('vcf_extras.inc');

# Remote detection can't check for SR or multiplatform firmware
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var app = 'Cisco IP Phone';

var detected_on = get_kb_list('installed_sw/*/Cisco IP Phone/service/*/SIP/Banner');

var report = '';

foreach var item (keys(detected_on))
{
  var portproto = pregmatch(string:item, pattern:'installed_sw/([0-9]+)/Cisco IP Phone/service/([a-z]{3})/SIP/Banner');
  if (!empty_or_null(portproto))
  {
    var port = portproto[1];
    var proto = portproto[2];
    var app_info = vcf::cisco_ip_phone::get_app_info(app:app, port:port, proto:proto);

    var mod = app_info['model'];

    var models = {
      # min_version is really 12.0.5SR1, but remote detection cannot determine that
      '6800'      : { 'constraints': [{'min_version' : '12.0.5', 'fixed_version' : '12.0.6', 'fixed_display' : '12.0.6'}]},
      '7800'      : { 'constraints': [{'min_version' : '12.0.5', 'fixed_version' : '12.0.6', 'fixed_display' : '12.0.6'}]},
      '8800'      : { 'constraints': [{'min_version' : '12.0.5', 'fixed_version' : '12.0.6', 'fixed_display' : '12.0.6'}]},
      };
    report += vcf::cisco_ip_phone::check_version(app_info:app_info, constraints:models[app_info.model]['constraints']);
  }
}

if (empty_or_null(report))
  audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(
  port:port,
  proto:proto,
  severity:SECURITY_WARNING,
  extra:report,
  xss:TRUE
);
