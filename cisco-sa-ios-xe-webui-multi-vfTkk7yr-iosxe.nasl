#TRUSTED 127f3fb99c0309f7514588d1a2f96a198bda475f96b767a26b8c102c5d4136f656dcd6104e0697cc2e892754fcb4c5198d84230572bd9d3c3c978faa13fbbc80e4b7ecff308d48fe010d0549bd1aa8e236bf6d27f76c31c1eb5e5a74f81b7f0a564e84119ac5c5fe3af88f3a452283ac5e4b311923f9b56258c2800e084061810b3a18a55572225c1bd1d5c2ff09428b060246a3205a0a6c7517089e616631470c25acfb89c3fbfd41b9cdf6109e815536197f4cb2d5f52a3afa77a6b752827118c9afae3178158957d6aa6d709abbdaa9e28734235db94590e8a0192dbba13d0fc530af539e2e28d76b8cf8a52a9633dcb9b2d1f6d85c422ab379154464b6195c84750eea2bf14fcef9f53ddba90481d43eb24ae04ca88a0866846a9a6a658559a540eb73c1170318ff5e3e6f9c977314cbddc9c020d68b43e7bc761f1bf9a7d13f26e0f3378c39286966dc143f73fe55cedca9010ee48dfe1b3667ae6d6c22d79648c702edb97b79bea19eee5d9dcd3afd0b5dbb267e97483de28554dc7c2bda1a9f3c70237e339d6783dad54fe38dfb4f624f5c0d90e9f03064311353dbe7a42a58a7fe24b1f2251c0f33c7f46b6d08d82449eb461c37506790db40626ec5611001ca500310589a1672c85868dd6e86510264efd78da4987bee3221bcaff4687825405cce6cbe3a4d4cb4760982a96d63205542c833a78a5f4345c1735ae5
#TRUST-RSA-SHA256 1956806d4c0510de32b4ba9b2d446e0b37913f44dae4b65c5ef27f06fff37a7ced7434c80675fbd018839a6d9056fba5bb8eba18378c3827bcb505a8e0463a0398487f02e53165667e319bd663da59c73bbee55d416c8feb00288cceead90af199c6884268ce517b65f95180a4b715cb7d994a4b649dbb12986e8f6410205b72c09b9fa1066738d7c5d8a7a242a3c0610770be82fc158453b65e774fabe2d484d27b7f65a5425fe8a3916ceb0267bb784a65059207355c4060a3ed6dc88f31c1b39340fd8f91f143c09908d3d159064c2b62ce17bc89d5eb84ba2037a2f41368e250c3221f61fdbc569ee59e9d65273b6eef257f4daf9760283c4f7ad8d944d0a42a6c48e6d5ce1641f3b34aeec7c338b7c2c4a005459d321535f45ef9939fee37b521aedb24ccbdc8939f1e96d3981f65024e842896348505d97b2b3aaf02a0b0e35decffac0a1fd818f18397512c275963e2ebbd0ddf3da3888856b7b0e8bcb4232b31a116c82c423ec5276221f8656ab4d475e1a17b85a47c6ee256cab0a53fc36a06f3a61afa85624d8455e38143804819dccba084a3042fa7af4b88773f78a75d4474f9847ed9e67b87dd947758889800eb0fd1c254d0eb359b18dd88619289f97d943f4afa1dd2452b4705fd4c45063231c14a87e790ba49bfdcacd22d493925c786d4ee41e78faa9d536eff8d5f8e8a704544ffe17e64c74703e483e2
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141172);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3474", "CVE-2020-3475");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs40364");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs40405");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-webui-multi-vfTkk7yr");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Web Management Framework Multiple Vulnerabilities (cisco-sa-ios-xe-webui-multi-vfTkk7yr)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities in the web management framework of Cisco IOS XE Software could allow an authenticated, remote
attacker with read-only privileges to gain unauthorized read access to sensitive data or cause the web management
software to hang or crash, resulting in a denial of service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-webui-multi-vfTkk7yr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7c030d7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs40364");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs40405");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs40364, CSCvs40405");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3475");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20, 269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.10',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1t',
  '17.2.1v'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {"no_active_sessions" : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs40364, CSCvs40405',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_versions:version_list
);
