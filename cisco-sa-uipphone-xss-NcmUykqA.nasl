#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186612);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/18");

  script_cve_id("CVE-2023-20265");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf58592");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf58594");
  script_xref(name:"CISCO-SA", value:"cisco-sa-uipphone-xss-NcmUykqA");

  script_name(english:"Cisco IP Phone Stored XSS (cisco-sa-uipphone-xss-NcmUykqA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device may be missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IP Phone Stored Cross-Site Scripting may be affected by a cross-site
scripting (XSS) vulnerability. Due to insufficient validation of user-supplied input, an authenticated, remote attacker
can conduct an XSS attacker against a user of the interface on the affected device. A successful exploit could allow
the attacker to execute arbitrary script code in the context of the affected interface or access sensitive,
browser-based information. To exploit this vulnerability, the attacker must have valid credentials to access
the web-based management interface of the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-uipphone-xss-NcmUykqA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?967af9fc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf58592");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf58594");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwf58592, CSCwf58594");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20265");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:ip_phone");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:ip_phone");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ip_phone_sip_detect.nbin");
  script_require_keys("installed_sw/Cisco IP Phone", "Settings/ParanoidReport");
  script_require_ports("Services/sip", "Services/udp/sip");

  exit(0);
}

include('vcf_extras.inc');

# Remote detection can't check for SR
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var app = 'Cisco IP Phone';

var detected_on = get_kb_list('installed_sw/*/Cisco IP Phone/service/*/SIP/Banner');

var report = '';

foreach var item(keys(detected_on))
{
  var portproto = pregmatch(string:item, pattern:'installed_sw/([0-9]+)/Cisco IP Phone/service/([a-z]{3})/SIP/Banner');
  if (!empty_or_null(portproto))
  {
    var port = portproto[1];
    var proto = portproto[2];
    var app_info = vcf::cisco_ip_phone::get_app_info(app:app, port:port, proto:proto);

    var mod = app_info['model'];

    var models = {
      '3905'      : { 'constraints': [{'min_version': '9.0', 'fixed_version' : '9.4.2', 'fixed_display': '9.4(1)SR4'}]},
      '6901'      : { 'constraints': [{'min_version': '9.0', 'fixed_version' : '9.3.2', 'fixed_display': '9.3(1)SR3'}]}
      };
    report += vcf::cisco_ip_phone::check_version(app_info:app_info, constraints:models[app_info.model]['constraints']);
  }
}

if (empty_or_null(report))
  audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(port:port, proto:proto, severity:SECURITY_WARNING, extra:report, xss:TRUE);
