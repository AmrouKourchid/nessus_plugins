#TRUSTED a93d3c73653731e169bb45e0138e8a090979cb199b79daa5b8a23a2b60d5d67acfde99a4f42f909ae5ca149317041319202515f808c7f4ed1f1a84f094c82a5c723c2fc92e4b7e0a7e86ecd766957e08fc60eb4714cec84f70c88650cfce367eb1ee2b11a9d4737dc38a8e364eb205acf93947af46efb33545ebf803b96dd5e118e734c4d0a6e632952d37e729e3590ae2ff78d4b96c68ccf0acf3c960550004fb60a1a6b19c06986e3a998386e04494f5db2c316a044014d56bf8557322b726b37816868978005507b76f98b0de1a13375da1dfba667d636a832c052975d0a92464c1be4960951b73148a86fdfc1e0606761035cbeb40f6b2f9f21b8803727ee211d65d5446408e71363e8e42c61262f0d48a7208b78e4c8bc2c4b49a116414dd30d16a4561d0c9608cd5941192b2e86846226121b320b12621e3bb164e01a8c5bc6c3d53df63168944126abf48987932a6fe05cf340ecb173923a17bbf7a77282a79eaa8b342d67af44385c5922e0ffb3023d75899ca2b7bfcaad88c2c64165dcb06fe85f404fc6883cea06f0f7deadb86a864f6e81c081e74da2a82f9f17b148f6c45c1cf7f8b9eba75613d64e2975f5bb5b56b950713c74feaa04b8df9930accd8f3257a588c8c0636db04a68710bfa9a31a8fa9858c1697bc87a7fb12fdaebc46d940b69d38f81033f0261415e300515b8a051a2694b7689fb9633e1ddc
#TRUST-RSA-SHA256 2e8b4c01eea3d2e3abe10c0ca62abbee90c4df431978187a056c246c0ef6008cf7f4b101b67f3ceb9bd12332423d01f061bb7334ad2a0d403efd12db23e69c069819f4f575f0d4c3bf364852570eedc55b669b0612102d335e6357c2d2e4dcc8dd5abacdda8132fdb16926c3f0bd930997db3988290b0c1019bcf8fe2e0370985ebfd6c77e5bb1efcb102933fc32b2ee98426b72198c31821b021e439b4653ac9521719d23ac4df7108eee2127b7b1a0a53b5811234b2b660f6283e336c77f17143859527325b0e949dcd645e28a0506a3e5b9c6ef042a22636fa614c2098f6333192c5d78d59110017c8bf93efde125560f834517d60dcbe949a506be34c93eb362e280b98a450a260d8d73799265f33ebe12557dcc1ea6d92ab991021fd39bfa9f7277a9384402c94fbadc0a130e9da427676acd9f9c14b898a2318e50daa05600c1b36195faaa991f583bdda01f7b6961f2b1147100ec441927e45596099caeb5bbc1e90a82b2ed24f3e9a416188a74d3b78a9ef0279ed1ff0882dc07cb543ed6e9d45559a97fb83325a2b72b3088eacd53f869ad33e4d523cdd2bd6e083ca9fb986f17a08b416b4a7c133f791bc8e9cd17ff9c0395d19eac57ee951ccb82d106ec210d7a113b106ae766111c462eba7bff52d6e79dd37b1691d81522ee205b47f66e50b319e980be77685893a80877e9b69fda5872d21bdfeef2c254aad1
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(215114);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/10");

  script_cve_id("CVE-2025-20207");
  script_xref(name:"IAVA", value:"2025-A-0082");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk60819");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-sma-wsa-snmp-inf-FqPvL8sX");

  script_name(english:"Secure Web Appliance SNMP Polling Information Disclosure (cisco-sa-esa-sma-wsa-snmp-inf-FqPvL8sX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Web Appliance is affected by a vulnerability.
  
    - A vulnerability in SNMP polling for Cisco Secure Email Gateway, Cisco Secure Email and Web Manager, and Cisco 
      Secure Web Appliance could allow an authenticated, remote attacker to obtain confidential information about 
      the underlying operating system.
  
  Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-sma-wsa-snmp-inf-FqPvL8sX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d920caf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk60819");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [ 
  WORKAROUND_CONFIG['snmp-config']
];

var vuln_ranges = [
  {'min_ver' : '0.0', 'max_ver': '15.0', 'fix_ver' : '15.0.1.004'},
  {'min_ver':'15.1', 'max_ver' : '15.1', 'fix_ver' : '15.1.99999'}, 
  {'min_ver':'15.2', 'max_ver' : '15.2', 'fix_ver' : '15.2.1.010'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwk60819',
  'fix'           , 'See vendor advisory',
  'cmds', make_list('snmpconfig')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params: workaround_params
);
