#TRUSTED 8b4329a6251f34fb3706112e964f25e1b769deef8d90ca72c35d8e37c72083977334261a246df7af4a74f7a4d25c77224a1a3815ca908a32396b4feaa3d1690a338fd4423e61efe72dcecdf826d1701493ff9529d505f3c32b22ec632418d88b8600a11ad96f5dbde521fc1fa393fd9b46d50a71d77de8f8938d12275638bb7bfb563c9d1842cdf4102481484938cb8a57b11a99688a0891bf60195e28517c0e070e52ffbb81c9b9131b31b4a1dfa4622a9dc6d803ffb5220a1609f06c914c0e9c645de24d04581c0d546360833b97c28f922b67f195be45781b8f6f9e2e39062f9b7adb81f7b08f255f9f1f444482b05a5e7a8e6d7359aee3b15136a11d9dc8d56b750aa52bf2c747eed6533ad2c533cdf0850e89f691d3e012d98cb223d2c257c1a515011610094abeebc5b799fac50bc5be16f01f3883c4c9083492f69fb084eda6b2523745a6b5704578867928ef6db5168506c893f591c621745223fcc3e5c2362d32ff95d2a9f6e3e0cd59047fd71e2f403f96771560776f8008faff5d16cca449b617973d7e04243eb1cb74ef1dbd63c923d60026874fbb227650b1f3b24878fb0f111d154631c384f913acefe4334179bd0ff1a32f421ee836da0ce1da40650f71260f36c4f12fc1ebd1f9898ff6eb395f679a65bc1cff10ad3acd5f3755af644e30297a9e2029d57eb9d839104aea1d692675de54775ae0f2a8e2cd
#TRUST-RSA-SHA256 844f393df8adc443fcc3437cd73b14916db821154110ede181f588abed1ffffe4c1ee1a71a08bcfba6f341896edd31b0e03ce1ff26287466ed1b2d607ca693f946f1b7c94b6f2b5d6931e4ea97b0096d5f4ee68a6a0c0057208af45ef5a28eaa29661bdfb185992288de5a1232e9b4834d893ec11ad02d61d847ac413e503f039a5271e05c86e4c5655ac9985470403ab944c7ac84c1c144f72c4db47cca75b909c1aaf9e099e9edff8836db0e995eebf2307ae20a7978736ccb0c9a884fe055f56ac0994c9df321525c85bb2e022fd39f297ff1ad7aa92ee3c09822282a24742ffe096f0c3d59780f0b8037cf76261390defd116827574b258574ba5724d751f2500fb87d3700ca061877e48f8896d2b888145306264e43aebd26285a01f5614d95cfad759910f05daa70b569ee7aa5969049deacf0e14c30136ef3224fa43067418d2521542043a93fa7909bb3da29ad5bf5817427b13c7e014a344cfed1ad5685ba0f4657c12825689c7dab9603a3bc1fdf2781f41cb4cf6b02790e05871b8a29ce76144654246c4c6c90c6ee0486db86625b7ca00d67f2a745c853b3140952d3c1269361d7d310acd3fea73d683c9a33782cdc280bcfccd285caf3662166f055031d279b2f5148bec312d2dfacc8d8b59b15dd9e619b0b07b700d28c768b7913cc8db6117c0a6cd01a6ab25cc22940aa2e1a65925826aa1436485f3a2526
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216595);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2025-20158");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwn51779");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwn58742");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwn58744");
  script_xref(name:"CISCO-SA", value:"cisco-sa-phone-info-disc-YyxsWStK");
  script_xref(name:"IAVA", value:"2025-A-0117");

  script_name(english:"Cisco Video Phone 8875 and Desk Phone 9800 Series Information Disclosure (cisco-sa-phone-info-disc-YyxsWStK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Video Phone 8875 and Desk Phone 9800 Series Information Disclosure is
affected by a vulnerability.

  - A vulnerability in the debug shell of Cisco Video Phone 8875 and Cisco Desk Phone 9800 Series could allow
    an authenticated, local attacker to access sensitive information on an affected device. To exploit this
    vulnerability, the attacker must have valid administrative credentials with SSH access on the affected
    device. SSH access is disabled by default. This vulnerability is due to insufficient validation of user-
    supplied input by the debug shell of an affected device. An attacker could exploit this vulnerability by
    sending a crafted SSH client command to the CLI. A successful exploit could allow the attacker to access
    sensitive information on the underlying operating system. (CVE-2025-20158)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-phone-info-disc-YyxsWStK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4cd3682");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwn51779");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwn58742");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwn58744");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwn51779, CSCwn58742, CSCwn58744");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20158");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/21");

    script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:ip_phone");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:ip_phone");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      '8875'      : { 'constraints': [{'max_version' : '3.2.1', 'fixed_display' : '3.3(1)'}]},
      '9800'      : { 'constraints': [{'max_version' : '3.2.1', 'fixed_display' : '3.3(1)'}]}
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
  extra:report
);

