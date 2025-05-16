#TRUSTED 795d52e307769db584fad177acea8e8986516035a968f2e4675fd277ece08a4ce13cf3d9d286974af82770c72d341f330f1dc7dd0978f492def078b9ef62d8b909de22c1cb14119da744f60c4ff0514ede9b2d8d1af96c6bc3e686d54c4e3e827ebddf94936098c3f4c45af2098cd31084b796df96e7ab99f88d6fd76a0a2b94be92c4220a327ac01c1c90a471b098e3b15e63940218710559c2d9f3d5daae673859a55792cc0c2355f7f804b438dae10ab84ccc32df48241d3bec0d2846ecf13620f92f3f64fc9082479f71af7279915f4b1ad7429d69cfa8ea7ef7571375d6e09866122cdb177a46efb1d4b5cac24530aa7c3a083404f908bdcb886578fb0963d3edbc246038b173e47788975b57308f06dbb277b470ff0dffe3af3264e0aa9d0434952d3882db33baee18d53681a2fd48ef1d2beaaacbf4344428bc323ec2efe2b38dff6648c7cb3fb7fe30448682154bfae31898a673bf48e22b8cce48c0b67c90112b898c7b2012082388bc25778aed28190923008520104da1b599e9e426ba6172f7ad4e7d66c23c89447c801a491a0d77cb49a8f09c364a24b8ad8e31e35eb5998dc6cab41d6459820bd1ecabcb02ea9550dcc5d25b66c7886635b12c4342a54cfa84bf9f6a5cd7e38c5d0bed43cbc79139c68867aaf671daf153e35aac4b6054c3b9c99e4cdcbd178f9728134e34c8f53861a0a018f07e9383791293
#TRUST-RSA-SHA256 87fea31683c8bb3fad7a677bcbbd0a4ee3cb13f23f41b0ad2ecec9eee44ebb20b7a5e63f16d256e518fecb99ef789512b449ae78625439f1b8f5d8ba7e4b65f5e6af4be8dff08904469675e2cb075c14dcd3a666b094f9af21a6a07e92053e2e9e274ebd4608aa9d29ae6db7b8f1a7c8bbe5534042aeb75b08371782e366e425aa3e5f9f7af90731b17d6791654e8b41ca374fca2174c4f7617a42fb5d09c140998fed75c4e500ae481a001eeb55d03b4916554753f55d1d7765608fd4d0bfb1575b0ed9dcbf40e0336151f3a85c64e3e502d88c4cf1da8619762f13f68045158a730e2ee26ec853e90876be8578309a0552d4841d6a5fe43fcb80994d3f6ce651ee47446997b3429360711543a01228dff1c64d9ec027f4a8d9e85c1f841c02bfa1b4624fb61c5d5ced493bfef157ec25025eabd6f6e946c7dc10f6de4cd7639932ca1df6e812154557233861cb74e2fb4af5f87a975e2a3d18f51b0be9b4007e11f6c2c24ec9c351e51ed618079334149604f5ccb59741994228eb9500af34548a92ba5eae2435ce0aaaf7f87b5625588a94336899796ad6285517a54c20d8008e4bb8616be6eaaed5a9dd9f2ca7443cedb43076cdd02a54babe4e3876bf94b3243ba167d359073f45c94a848be7002602fbee397836bc3313aa1e77c30653797fbfeebf59a8e131419bd1b7a0f90206cc455c8133f9855f675904d1a1281a
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184457);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/06");

  script_cve_id("CVE-2023-20071");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd83613");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort-ftd-zXYtnjOM");
  script_xref(name:"IAVA", value:"2023-A-0596");

  script_name(english:"Multiple Cisco Products Snort FTP Inspection Bypass (cisco-sa-snort-ftd-zXYtnjOM) (CSCwd83613)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort-ftd-zXYtnjOM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab2357d1");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74985
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c46133c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd83613");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd83613");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20071");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.4.0.17'},
  {'min_ver': '6.5', 'fix_ver': '7.0.6'},
  {'min_ver': '7.1', 'fix_ver': '7.2.4'},
  {'min_ver': '7.3', 'fix_ver': '7.3.1.2'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['utd_enabled'];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwd83613'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
