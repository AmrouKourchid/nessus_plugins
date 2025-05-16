#TRUSTED 320a3e2d3e93c83c7211c5006d72476bbfa9550b45434995f2f2a8a25eb6095bf8a0be992011a828b2a35c5aca50b7087a506552370fdda11bc1187e15e37ab4d31abe45a1cde95b52c6725c7df400933af8f0eec196132a583e999b051892975643330be6e10e9eb821bfed861d5871da3d923591f792d3cb0a5f832f1f1f9f5f8894926289d42707cdebe7e431e6b8851c21d37126d4dc623a6a9e03ccc5057266bf71457e260603fcb77cd42acaeced39bdd6e2c89d199ae511453427feb83bafdc77291339cefeeb930790a22c2026961525ec96b43fcd9d79a17ed30c80e53f7aa85b1cc09cf8d129a3c4549ff9864a128d2230fe91e700c5deec652b0e0a478f73068815a61a08edee04f95bbe6dbe4dd4eb9dbc73e0a2c34cde2fe6ba3f624774d41f0ffb33e4820cf4ca93b958b264e3a71982818a3478b3fa02059e75310386344aa5f3fa640026071b6dd268a994eb814cb56bf904575874ce711b3310b9ce9933313a6c54e43f983912ee67d5bddd5da9b34c6afd669274cbcde45e5be86c1cad9a8372613ea2069477fc319168fcda9d47c176b6ec156a31d6c5942dee54a57c8f5bea2db735581a414ec3adb6f3dc315caead57fae6c41f57e89361fb3212f0c7be090709c5bbf70e84807ff750774fdbc7a4f0b9b2117e02a37ee8ea6385d8c69526cc55bf65b2bedc72ce5ab61f45d8d43781afef00f3d266
#TRUST-RSA-SHA256 03822e17afff11ffaa90b2024cb412a9721a8cab8ff4dc4b692e5cdb8e47a366f631cc8ac14845f90cd1aacd56ee89d5ae5d0c4a43716168b74a5d5f13d6895a5a34517c1a3447c660d9263c2506246d66d1e38e891125be70f3b7e5246abbc19fb0d48fffa09426295f36c1de2d8153045bb8a82bc2783f8ab6d02dac6ea9a4fe9efaf9e3cd8bb109e65bd175a4c9e0265e94769a7ac252b74ae7e77550b22af878400f085299435c56b839af03186fe66302175f01997eef59af47bbf2c0343d10f36b24689f244e4a18a650025f64efcadfa51f3ab11327f47c04f157c7413dff38c7ee266c01df4e136f9ee4c742e79801af25541b93c69f47780b380377f6ec4b32121b9d26c189f0c768beb78c61ad261d6038edee38c148ce62e99affc758b298857c4a0b75f53a7a8a68eb582494044a6d3c7ac372abd807366689b61852b486e1d609ff12078a881e68e12b5b1d06bbd8bcd8dade55ea4fec3bfef2193bc4d279d2fb23291791ac33a6de1f0058d5a10a3ca95084513928472e4f79256621a9a2745c10c59668cc8599fc6ef96c2ad9228d607a38c4131f77c744677efe7c1ba92627651566030c38e2f3ebbe7eec7b3d8e9d6cd482213bf9b17a586ff893aa6bd5956f80a4dc6beee4a2f4bee920f3377d160fd89359d70ae11df400cbef3a15303f2a94b6ef5478cab8e89e86d1ac5a0c6317cbd6ede7d296f953
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133473);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0485");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva23932");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi95007");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-sm1t3e3");
  script_xref(name:"IAVA", value:"2018-A-0312-S");

  script_name(english:"Cisco IOS XE Software SM-1T3/E3 Service Module DoS (cisco-sa-20180926-sm1t3e3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability
in the SM-1T3/E3 firmware due to improper handling of user input. A remote, unauthenticated attacker can exploit this,
by first connecting to the SM-1T3/E3 module console and entering a string sequence, causing the device to reload and
resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-sm1t3e3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e768df6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva23932");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi95007");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCva23932 and CSCvi95007 or apply the workaround
mentioned in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0485");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info['model']);

if ('ISR4451-X' >!< model && 'G2' >!< model)
  audit(AUDIT_HOST_NOT, 'a vulnerable model');

if ('ISR4451-X' >< model)
{
  workaround_params = {'ISR4451-X' : 1};
  cmd = 'show diag all eeprom';
}
else
{
  workaround_params = {'G2' : 1};
  cmd = 'show version';
}

version_list = make_list(
  '3.9.1S',
  '3.9.2S',
  '3.9.0aS',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.6S',
  '3.13.7S',
  '3.13.6aS',
  '3.13.8S',
  '3.13.9S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.6',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.7.1',
  '16.8.1',
  '16.8.1s'
);

workarounds = make_list(CISCO_WORKAROUNDS['sm1t3e3']);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCva23932, CSCvi95007',
  'cmds'     , make_list(cmd)
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  router_only:TRUE
);
