#TRUSTED 98cad6ba524bb46cc85fa6a2f11cb554fde57c5ebbb181d904094218f7a57ab1f1b642872cbf4e01ae4402624102dbd75e27a005d94ed25d0a29764ad6962bcec4a627b924ecbae0de1b6aa09a1d02af858ac4ec5fb0c1046164469637f31faf9f24b0f58618cae2be4b0b0f2ed211ba1087b49a08c11c45e5d7807b75b127c6fabbbad482d7b463b699589b220ff11630e1d2d1baab571ea6b4e5a923bc4441e453e3ba75881977d5760b243c021cf165faf2d2c53b530af49e30cef97903ce2977c471c8a6338ea5ec3c9b1fa8c8ea899c639c6a79e2e14b2177c818beae183fab1fc405cc6813ac49c69793b0bd0effc15a0395296f386537c0a0adbac47955112b19bac2575f42cd3cc46499aeada3429733d18c321cf5eb0d8224e0e3a59ff9fa538394a0af116b530a936be3e598a1e5af6dcdbb39dbef27ba69df71603178375fb677d11f71217e933dcbd57504561d29f336cc7cd92da1aec2c604c8933f55879cf74c2b73326e4c4b832b6768c4b019adcf93ae3173866fa81bca702045d77d8c426a997b4d291d043ddd04b3338a51e5d18d1781d1e0f9fc6dfc3d38baa0911542f54d04fc4bc45caf4115d4ebb84f26e2afec179d13c8dc88b4afb6f4a4469c9d074bb35ce5f38ca3badf9367d9fa12ff4d21a3a6aeec1ac988cd02cef53d1e35191ecb17a61987d4f750628d37371bddde105c08e8e34b431a95
#TRUST-RSA-SHA256 0bdb85776b284208a4b42b5cdeb8549fb60824b6ff348721cc9ddf3e6fa0b34c1ca09b38fc84f646d4b0f62f72a2bd22dad4f41b07d67e0ffe47e4f6302e1427892053a42db9284a3d0d23857717196d45171e2c3a07e081e05c846d4c8e7c74702f590446250b9015f08d3a495ac085863e1a8a81cc10eca593d392fb59ce3110f6bb2ee6fc2f837b4beebf5210237750e5233fed10bc939d0add796d2e7ec2ed962ed57582dbe2b4f3b4cce60476da81db6f284a93ba38feae83bfa5bac912a4badd9cb2bbb9b612254d73bf2e0d6d3338879e2879aa9ceabf54e608e0e0466d6006bb9d39bac6f697f3717a138e6e3430ca1033ff32f28ed3f049452fd6c82786065f89dbd708b391593120c5b498ab6d8b5b80c070ae0426d2dc167465bb4daad95390230c31b10cf5df523899e53b83329d667aa24e1af65e6f80c2f4509b593c6b0a8459f3a2f0d679d9b30bcd49e7b2d05cdcd7d1efaf7c8c6591f872067287b874f4fd4c21dd93dfa17236711cdf5738f0001ea4e64c7665ba7ff95da86f5cdb954a0b507c6b82b447bb0a54d73a8781858b6f0d35256c0f240ea57f2ffaa4803dd76c0c291f03cc961029976214fcd3d59343bbd11d3e20f9701d9cafb788cc9f4ecd629268bb270372c5f50895ddc0e3d162d4abdf86fbbeec7bd6f7ff67953db47a50298ccf0ba7addbb6be2197aaf3012ffa2efbed72752d350b
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192920);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/05");

  script_cve_id("CVE-2024-20271");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh00028");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ap-dos-h9TGGX6W");
  script_xref(name:"IAVA", value:"2024-A-0193");

  script_name(english:"Cisco Access Points Managed from Catalyst DoS (cisco-sa-ap-dos-h9TGGX6W)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco access points managed by this Cisco Catalyst 9800 Series Wireless
Controller are affected by a denial of service vulnerability. Due to insufficient input validation of certain IPv4
packets, an unauthenticated, remote attacker can causing attached access points to reload unexpectedly.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ap-dos-h9TGGX6W
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4c9a434");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh00028");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh00028");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20271");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:access_points");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl", "cisco_iosxe_check_vuln_cmds.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

if (model !~ "C9800")
  audit(AUDIT_HOST_NOT, 'affected');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['vuln_aps']
];


var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '17.3.8'},
  {'min_ver': '17.4', 'fix_ver': '17.6.6'},
  {'min_ver': '17.7', 'fix_ver': '17.9.5'},
  {'min_ver': '17.10', 'fix_ver': '17.12.2'},
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwh00028',
  'cmds'          , make_list('show ap summary')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_ranges:vuln_ranges
);

