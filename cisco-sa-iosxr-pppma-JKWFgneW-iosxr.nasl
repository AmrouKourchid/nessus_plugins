#TRUSTED a13a8bc71ff166362a7d3acec47b3b1d348a154c322a2823a39d717843aea16e2b1a395f6d4bb187d64a1569a663330313e26a0922d95042c6e18e7af918b3a4bf1e282fc4d1103912fc061aa84f79c3cf36e22064b8684e3bfef541080db76070c502e655a334a2910c9674070362a3352bed75b0d4b84d26d5970a6d936ab6e1ee3a48d7f80af4d42b10b67aeb86be1a3193c8c932ee7492b756a55dcca90380ec4c68d6ef555b67253c5e8fc6f647196f06b7ea414e48ea225167a81db6c3c5321c7787d963091fea8572af70871f0a37355f71b18d5a21c612c832f38c76deb9dc6a57457865b1d494409933f91880845605922ccd9f78b02c6b97f7b130ea09f67dba7f76b0aa16dbb50015da531ce11f05602a2747b0f462543cfd5af82f54804a52c75518f752c5c42aaecd87c6330ce8618ca3d6dcabe381759d8c1ea45632a2ce7ab49c36cafe163ed33528bc1577d53d2300be65c951ecb2e03218148e62ac461d628cb5645c0d6c7694a899b81bd093c7dea6877b948337c5b859a80361900ce6a5d93cfb2239c05a6b8172ff221efc5ffa92ebbed623e05d87f97a52595797b908a979540d82a09d8c28c526e7bb540da53cf99e95fa22223c2723424c7f54abed861f440388677f52b19784b152fe3c3838181cfb3cf41d53e38efe099e6fff17187d453436f08798e377c8a982bcf67e0161d071635222d23d
#TRUST-RSA-SHA256 1cf5dbbd6e6ee8f3579a93adbe031acbaa7ce1cd2b799cc1bc274832aef798b98b8e5f06c04bc44c2bebba6627d6a35ca75dd128be165c76a82259b35aea0af2fc38096e5b212cae5ee96ba8b672df2cb11c5f735698b42e88c8aa8f9ede9f897c1437f8b57d39f153db782375bc79cc4a4e4d0f4e40e590e009eb3edb3b49b3c8e6a5f9eb0b42c7d4dd2e4dd95ba1663a1cae61957863ef7349b08cc9f0a97837eb2798039855039246d4ea1ef8fe57dbfe56c9f26b2fefc85508bdc437061e23250aeaef21cebdb854c5144f7a87fd2363008a00c1ef5b56ad5178bc4113a3b87e222c1ea8ebc351381cf36d512dc9c7a5865878e02f39ea7797953f57a3f94e96293feebcb303dc252d76316c066fd78b9e0e06011fa15b3b885a5e559f16c2bf62e5a74698df2fa4c07a5ecb39e1ee07f6c04014db95b13bdd9a9c61ecd9b2f87321fa518b97fa7bf72a1835ee0f545cf5ad5a8d26e92779cb9aab1810b04c8a97a096adff0229079599875619981773ab21cfedbd875392c0791eeb40ce4835f38844b9eeae74818000bb1a09f6c4c327ae975ac16eaff5dd4e728898ab55a86fbb83a93632a0aafa19488bf1c8743707ec58c8a8693e866712c25b29822828e2e612510726712f67c2a2f5c7a9cbe1b85c85ae62f9126fefc64058376530befd8447a2f500a9acfacf946c4b0505278139b3f25da0e98f481a6f78296a
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192235);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/04");

  script_cve_id("CVE-2024-20327");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf75789");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-pppma-JKWFgneW");
  script_xref(name:"IAVA", value:"2024-A-0169-S");

  script_name(english:"Cisco IOS XR Software for ASR 9000 Series Aggregation Services Routers PPPoE DoS (cisco-sa-iosxr-pppma-JKWFgneW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the PPP over Ethernet (PPPoE) termination feature of Cisco IOS XR Software for Cisco
    ASR 9000 Series Aggregation Services Routers could allow an unauthenticated, adjacent attacker to crash
    the ppp_ma process, resulting in a denial of service (DoS) condition. This vulnerability is due to the
    improper handling of malformed PPPoE packets that are received on a router that is running Broadband
    Network Gateway (BNG) functionality with PPPoE termination on a Lightspeed-based or Lightspeed-Plus-based
    line card. An attacker could exploit this vulnerability by sending a crafted PPPoE packet to an affected
    line card interface that does not terminate PPPoE. A successful exploit could allow the attacker to crash
    the ppp_ma process, resulting in a DoS condition for PPPoE traffic across the router. (CVE-2024-20327)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-pppma-JKWFgneW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21efcd75");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75299
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3206828a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf75789");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf75789");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20327");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info.model);
# vuln models
if (model !~ "ASR[\s-]*(9[0-9]{3}|9K)") 
  audit(AUDIT_HOST_NOT, 'an affected model');

# vuln line cards
var card_list = make_list(
  'A9K-16X100GE-TR',
  'A99-16X100GE-X-SE',
  'A99-32X100GE-TR',
  'A9K-4HG-FLEX-TR',
  'A9K-4HG-FLEX-SE',
  'A99-4HG-FLEX-TR',
  'A99-4HG-FLEX-SE',
  'A9K-8HG-FLEX-TR',
  'A9K-8HG-FLEX-SE',
  'A9K-20HG-FLEX-TR',
  'A9K-20HG-FLEX-SE',
  'A99-32X100GE-X-TR',
  'A99-32X100GE-X-SE',
  'A99-10X400GE-X-TR',
  'A99-10X400GE-X-SE'
);
var card = cisco_line_card(card_list:card_list);
if (empty_or_null(card))
  audit(AUDIT_HOST_NOT, 'an affected line card');
  
# add smus if applicable
var smus;
if ('ASR9K-X64' >< model)
  smus['7.5.2'] = 'CSCwf75789';

var vuln_ranges = [
  {'min_ver': '0', 'fix_ver': '7.9.21'},
  {'min_ver': '7.10', 'fix_ver': '7.10.1'},
  {'min_ver': '7.11', 'fix_ver': '7.11.1'}
];

# vuln config: BNG with PPPoE globally and on at least one interface
var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['bng_pppoe_global'],
  WORKAROUND_CONFIG['bng_pppoe_iface'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwf75789',
  'cmds'    , make_list('show running-config pppoe bba-group', 'show running-config interface')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
