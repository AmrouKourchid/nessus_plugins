#TRUSTED 6f80ee1e4897488e4f34766fe733dd1959537eb80e0cc8a4b76426889d6a401d3d19f032a51f50d41b280cdc63b84032899f45971bcc0ca94bbbf55056d336c27358f4318eab5eefe6c38fedf1dc340059f12f6e3252ceea3b9df40b2603e2100623dd4df12867c8a25535d405783bd546407463ee999e50fbadd8842a74a57c5d4d18478975880b452b1cc8d505eb7547ea0c102d86352848cd36d9006c27414d8b43c226b15546dd010d97bdb70d46970c27f14745444020f12fe22ed4b233d3da06b5743966ed07fe95588db60eabeef49169b0f168e296890ce7351e1051579abcaebca971ddb8e22d9788829ca60ee91a3630223375d867fbfe4016a6ac83cb7240667e5a4107c6be36146f517b0c586a9eff4db86205f23e58283d5c4f5c08c482808131beca166e20748ee7e0d6044e0c1c5f20fba35b1956fa980b262abc8975173671bde0b863086dedca96c62c6864a53ae79b1f6d7e65cd01cffcb7cdbbce984c13c42694ef3cd7be61c57830e8c3800637bb018c30f070c3823681b532df0f8416c8b8406521c096b61fdd436ac7dfa24588dc126701c81d3056c57bd8ea51a2d3110e131219ae69ab80246c3700707d6cf1e870f00040dbf9d6695c656135ac883918319f385d378944606a5b0a189fb463b256a56262b9aa3389e79a0a43bd84394454bde21dcb47930ccc312353418c62b9257f082022e7e0
#TRUST-RSA-SHA256 6f8cc778426b2e6a001bd4c372473eea0d78506989db83149ea4771cd03201e51ec32387e5ad6fa7aedf82898e554fec3454c7b92c6cd49471aacd3737572c822bd28ae316f64a51f7040844cebaed9faa71e4dc894b8d5df7f0cac12c776fdda352d148bfddc1c71c51188bb039f208a7a11fd84205df8d2b74f0524ec2b60f4aa413cb354d2c6ff647b369dbff16c9eefb9094a0a9d0b8770813895c8a0f8fecb431db419a6063350e88d06d17e1958f372dc526c507f9d1e905cab8e05f51e504baaf3ee0103458480c97c0d9ca0aea68f1fe6189f7138c73a54a3151cf6a27c3483dea9840cd457d1d17437d849536e45748cf5b67605b6a34ff62c9b8f2f2296b3644da39856c41f9b9dd0082288f4330cb53f04e39c54df19a7b0e953f387d9722c51a7cb062ae9b1ea730671e2c4b0c28f06e25b687639e5038284f712c769a05b3a246d57ee994b03f6aa27fad16adbbd2a174b6eba3ceabe308c5f19d95a5e5497919bbb038bf40c46cd7a6183bbe39297c93c9f6d2b9b44eb69b512b27fa7e18bcd6da15ffd3f1bfc7736744e1291725f9e52ed0ddab4a4dade604be88cbee267fb1c36d58ed3a4fe3ee24317e1c090d7bcf1d8e4a70627d023a3d6fb0be3055315ea75e86e67843840dddd22ba7c58e3d9bd3b271a63b97b98e662741c4d9b62a967f18c7db8c72bde5b1044c44787bdf89e86201a0a0bdceb587
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132043);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0257");
  script_bugtraq_id(103948);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg73687");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-cbr8");

  script_name(english:"Cisco cBR Series Converged Broadband Routers High CPU Usage DoS (cisco-sa-20180418-cbr8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability on
Cisco cBR Series Converged Broadband Routers due to incorrect handling of certain DHCP packets. An unauthenticated,
adjacent, attacker can exploit this, by sending certain DHCP packets to a specific segment of an affected device in
order to increase CPU usage and cause a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-cbr8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b49f808");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg73687");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvg73687.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0257");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
if (model !~ 'cBR')
  audit(AUDIT_HOST_NOT, 'an affected model');

version = product_info['version'];
if ('SP' >< version)
  vuln_ranges = [
    { 'min_ver' : '3.18', 'fix_ver' : '3.18.3bSP' }
  ];
else
 vuln_ranges = [
    { 'min_ver' : '16.4', 'fix_ver' : '16.6.3' },
    { 'min_ver' : '16.7', 'fix_ver' : '16.7.2' }
  ];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_NOTE,
  'version'  , version,
  'bug_id'   , 'CSCvg73687'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  router_only:TRUE
);
