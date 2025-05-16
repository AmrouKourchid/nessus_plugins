#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211466);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id("CVE-2024-20445");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk25862");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk25863");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk25869");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk32410");
  script_xref(name:"CISCO-SA", value:"cisco-sa-phone-infodisc-sbyqQVbG");
  script_xref(name:"IAVA", value:"2024-A-0720");

  script_name(english:"Cisco IP Phones Information Disclosure (cisco-sa-phone-infodisc-sbyqQVbG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco 7800, 8800, and 9800 Series Phones Information Disclosure is affected by a
vulnerability.

  - A vulnerability in the web UI of Cisco Desk Phone 9800 Series, Cisco IP Phone 7800 and 8800 Series, and
    Cisco Video Phone 8875 could allow an unauthenticated, remote attacker to access sensitive information on
    an affected device. This vulnerability is due to improper storage of sensitive information within the web
    UI of Session Initiation Protocol (SIP)-based phone loads. An attacker could exploit this vulnerability by
    browsing to the IP address of a device that has Web Access enabled. A successful exploit could allow the
    attacker to access sensitive information, including incoming and outgoing call records. Note: Web Access
    is disabled by default. (CVE-2024-20445)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-phone-infodisc-sbyqQVbG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dee227b");
  script_set_attribute(attribute:"solution", value:
"Apply the fix referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20445");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

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

# Unable to determine if web access is enabled
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
      '7800'      : { 'constraints': [{'fixed_version' : '14.3.1', 'fixed_display' : '14.3(1)'}]},
      '8800'      : { 'constraints': [{'fixed_version' : '14.3.1', 'fixed_display' : '14.3(1)'}]}
    };
    report += vcf::cisco_ip_phone::check_version(app_info:app_info, constraints:models[app_info.model]['constraints']);
  }
}

if (empty_or_null(report))
  audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(
  port:port,
  proto:proto,
  severity:SECURITY_HOLE,
  extra:report
);
