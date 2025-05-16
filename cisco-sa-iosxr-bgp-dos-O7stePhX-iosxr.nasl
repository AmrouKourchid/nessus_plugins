#TRUSTED 30ea6134c841436f6d2e19741e9ec810297463468a8dcdcbbf3334e6cb99925161207cac23c11228c90eabf5c2a40fe3c041433b10cb36a5c74e665f701438ac690335c2fad947dc340ec60a1980a64800735286a28568b8f80320c5bf3d3b7a323be2d4a7900b3acfa10f74b0489f47555bbacb3c67fe98a386eb4357e336e02c569408207de0966296960da5514fc09bd5939e012a6f59c4456d10025425c8d3547bddb337199b6ccaabdde6ca2634b06486ff76ef27adb7ec29923c3a1722dcbf811a8001732870301523aaa36370f119892acf0e90c8fb6cd8734ef18d3f21c02420b7f42a3df27168008a233119a4eff51e12e789505ad1a1a7dbce587c698914c6d6c2e771498e873c4d006c756353c0a831597909e2ea4387790ee41177eaf07c705f27365f18c94627f1a27f1e1765c96ee5594abf829a1fc8279e19f55b2342605a43bf866aa7914fdbc8e7cb4f3eea3feb38bc64c59f34b40aeb41185df73faa9aa579ab2c4d057204f177c13b5a6566665500c44402476041b7d4ed834f0916f562bd8541ec4fe84e1fcb0902ccdfede1eefe6912b2e81f4140435ef5092df30d335c532d3a971c92ea79def1b7e685b282413f7681bfa65df39b50e94bd90ec7c6c756caead758d052b9401542b622ca03818360e5e8dbb8e28b675555686dc8210565d4ba2a42d5b690750f249c2f4c7c650c086f90c98d3f2f
#TRUST-RSA-SHA256 3c11ebc90027c74354f29d8aaafae87fa4007e77660d26d087770e0ea72862f78659e968bcc3533b0e2e5a9060b0086366881aa84888e59aa55b7be4666a9e1b508f25f9fa6b9661e0a8255e4d5faa43e7ceffeaa1fcb41a98795fc1c77d163939b9e0e3891f41a227ecb243d62df00dce88d1afc76d47d5f635c2ff0ccbbc40b351642248e62b2c56d5c3bd543bb93236ff7b0bc04f655db4aba531147cd9dbbf4685bcf95fd91f9e27eb5d9d01b0dcd9f2d4c59e98007b2f177d664c3b5a2f0c9392d20d3c9aef14c869d2845265f865a3713f59d94d3d3da3130032692f3950e0eacdae404c2edfb131d9387e643b2437b38c1d3d081f0a624ed1c9ff2458ea0a834b6e16d4fbb5b2cf28a65f2896fe7ff05526147448d3a2e731183f03414ae628b51d7b0f86e4fc8ce2d9f3395184344e9c3d530252243569945a127d35d0f1d816691a7d98e39d4889ab69ed2a812660934c521a4a5303794cb65bc4351ba1cc89c772cd7f3b7907a8382634942ec66ee6283e2d109ad815f62f72117b9af1b4d2444cfb9cdf1c227b72be29cf550caaec3f9f85621e7d28c64133bb942d7d7ed93d1706994d867e158b93d12c8e529bcbe656851d871d6cc45a9df9f5a9669171863e35c564aa1964998f0447468f03a6d84be0bf66b986ae8b546a0cc21542ea9504cb0c01b87e744593890453ca3d37744a4df52fe81d4239305a86
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232841);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/18");

  script_cve_id("CVE-2025-20115");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk15887");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-bgp-dos-O7stePhX");
  script_xref(name:"IAVA", value:"2025-A-0154");

  script_name(english:"Cisco IOS XR Software Border Gateway Protocol Confederation DoS (cisco-sa-iosxr-bgp-dos-O7stePhX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in confederation implementation for the Border Gateway Protocol (BGP)in Cisco IOS XR
    Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition.
    This vulnerability is due to a memory corruption that occurs when a BGP update is created with an
    AS_CONFED_SEQUENCE attribute that has 255 autonomous system numbers (AS numbers). An attacker could
    exploit this vulnerability by sending a crafted BGP update message, or the network could be designed in
    such a manner that the AS_CONFED_SEQUENCE attribute grows to 255 AS numbers or more. A successful exploit
    could allow the attacker to cause memory corruption, which may cause the BGP process to restart, resulting
    in a DoS condition. To exploit this vulnerability, an attacker must control a BGP confederation speaker
    within the same autonomous system as the victim, or the network must be designed in such a manner that the
    AS_CONFED_SEQUENCE attribute grows to 255 AS numbers or more. (CVE-2025-20115)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-bgp-dos-O7stePhX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?142863cd");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75548
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?402ef3d6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk15887");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk15887");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20115");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var vuln_ranges = [
  {'min_ver':'0.0', 'max_ver':'7.11', 'fix_ver':'24.2.21','fix_display':'See vendor advisory'},
  {'min_ver':'24.0', 'max_ver':'24.1', 'fix_ver':'24.2.21', 'fix_display':'See vendor advisory'},
  {'min_ver':'24.2', 'fix_ver':'24.2.21'},
  {'min_ver':'24.3', 'fix_ver':'24.3.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['router_bgp'],
  WORKAROUND_CONFIG['bgp_confederation_peers'],
  {'require_all_generic_workarounds': TRUE}
];

var fix = NULL;
var reporting;

if (product_info['version'] =~ "^24\.[23]") 
{
    reporting = make_array(
      'port'    , product_info['port'],
      'severity', SECURITY_HOLE,
      'version' , product_info['version'],
      'bug_id'  , 'CSCwk15887',
      'cmds'    , ['show running-config']
    );
}
else 
{
  reporting = make_array(
    'port'    , product_info['port'],
    'severity', SECURITY_HOLE,
    'version' , product_info['version'],
    'bug_id'  , 'CSCwk15887',
    'cmds'    , ['show running-config'],
    'fix'     , 'See vendor advisory'
  );
}

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
