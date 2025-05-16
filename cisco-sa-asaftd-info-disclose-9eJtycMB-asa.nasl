#TRUSTED 41df0113b088009fe6e6ef001303e74f53f0767e128df3e9e0c7c55c2bb2f7ba3ad5f44e8778bbee03e1e86407c141622bb8157cce47354615daa714787b4c12b44f7f4618e20f1cf50e82151f345b42e3c7b264dabdbec31836c093574a63831e2f679a0708e246b9cd03d4548f95a2372b9a7478070d8a948f995ff1569d01c51e3889baf35ae6196327d990ecdb3f3f220af76fc98c2180a8f9a2ff3f8fe8ce469a0db753a9b956600f08db7060db7883947d9a6bd3840e3bc85572062c5edde4e35f7835321ea39567359a60afcbbb6c38f8e8315614e9313767eb65ebf324ae553963e8d56fcb567036e77d8260862f8b1870b74cffd0e24ef7c1ce0461f6e8a343fe92a93f496bb13bde944965bc02991f21c7c296f5c58529a0eae823aec8833f247fc36b066a9750ca358b11fce52c9b10bad003fdc88c9dee4ad7b1a5427b46677a640df05ba8989f795018f34f69f4c2ec33c994bbb643a4b1b32e24975352f29a1d53031cafe0fe7c051df8b0360e1d4ad65d85793025f877d6560df3e97537940586bda5421ecdac1274b8f53bb7c197f3744439ba41394c48b10ccefae8f3794444af4ed8a57b1a81b4878b33e0d479ed44c01b8ba60da83888126f0be92dd8e1172306757c4298463bc89027b6688623ea42828cd9dda9071b0cdd2d84ae2e0b24ba3b426ed40a1dbcd7776c817bbfcacde74d5db65f284c7a
#TRUST-RSA-SHA256 97209a9d75410433923bd8e4e5ce2eefef5dc259a82af6ff1ba40a23736d04d712115c38bcec6f5f9e29d1a3246dcbab19f8fc7579272fa92e7c7d3f28126c7637f0f954437fdde3721fd8f9ca9bbd40b375054c32bd7a7266e186d4707a2be20db826641aa60ee8aa681a05c829383af1d87c1a0baa0e61e10d3c360e4112f17b8aa20c74a79b157864060200644cdbfca28fcf1d610b75c3382faba7274e7bfcd6ced00a676ff70f25b180a6667cee07792408919d85657b5445c53eaca46bb00de76f5b8027365b07ddc4127d9d8ca34d352a354f75367d9e194a5c362bfb526994c1a5bdf0106c31421b926e465dbdd6a50d0982ac0452175326d20bc31442e147ed1cc08364abb1bb62ba30d21f733f496396e69a03e0ba433ef33ce2bb17d047d0171312d2892a2fb25d8d4544f2a566b3a4a3765fffdbc270fdcc273818b3c40464f43af9b34a82869ebaf7b208457faa2a531b5e525754539c575c478633c5e6a96c46ef4ed5a64dc82a1b4634d17acad5bf7fdf0f8bd744c62ef8748e03de451e66dcc7b4d6c3a6615db132de43052975647ec4ea064028b807a19f20873521092142b5762efc0197f55a8e43e4bccfd5004c45cd6023b63f7c17aa5fe1c49994067d094392c9c42f8bce311570a93cabdc48c5c3937d5e1c74778a78b2238b3f4b993459ea286e373fac08e978660b91d54debef1ad3c404ba63bc
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137659);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/15");

  script_cve_id("CVE-2020-3259");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt15163");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-info-disclose-9eJtycMB");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/03/07");

  script_name(english:"Cisco Adaptive Security Appliance Software Web Services Information Disclosure (cisco-sa-asaftd-info-disclose-9eJtycMB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the web services interface of Cisco Adaptive Security Appliance (ASA) Software due to the
handling of parsing of invalid URLs. An unauthenticated, remote attacker can exploit this, by sending a crafted GET
request to the web services interface, in order to retrieve memory contents, which could lead to the disclosure of
confidential information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-info-disclose-9eJtycMB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca70b7e2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt15163");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3259");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '9.6.4.41'},
  {'min_ver' : '9.7',  'fix_ver': '9.8.4.20'},
  {'min_ver' : '9.9',  'fix_ver': '9.9.2.67'},
  {'min_ver' : '9.10', 'fix_ver': '9.10.1.40'},
  {'min_ver' : '9.12', 'fix_ver': '9.12.3.9'},
  {'min_ver' : '9.13', 'fix_ver': '9.13.1.10'}
];

workarounds = make_list(
  CISCO_WORKAROUNDS['IKEv2_enabled'],
  CISCO_WORKAROUNDS['ssl_vpn']
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt15163',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
  