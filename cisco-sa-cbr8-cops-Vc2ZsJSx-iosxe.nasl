#TRUSTED 2670d76313a636aacabc621ded3fd871c781255c5ff4fd3a267285a8e5db531af8db5e544faf903d3670173cf01b539e8a3230e1174f6f3705c3d23a87d91b0f4995c138fd900b7502a2da19bef67d5e2331646125d060bde96e6b4993b8714a03264c0bf8a83e3dc92256ae9636d7977f6597dbe3af89fee9b3072b249be24064af39f760c952d8c23c8d481d449fbe02e32c84c5dfb251b196b7f07845ae9ca97fa3995a40231c52e2fb07f63c736f950ecc9acc4a41dcc806ea19b30c766cf4f8e8cc6001edcd61254da6356ef6f9ca9f38bce4ce5bbdaf8df779f8a492198e523c7cc9a3a3c8d11225cdc48db7391a6d743b3673dd7cfe2b15886cff2e98833ae1b2c34695f9931e1c77b73ff1db47c3250b70b2c093ec5965db67627b840f9a2bf32aa653cf824e5c42cc85fc504abe73f387bdcfd4c67c49b3d54d25f9551112324158bb8840da6b7d931b5ec943945e14f456c7634100bcf5f9e580493b51ca1bc5959bd95a6450673c0f5e1e0e4f190a1f4eb14063b7ed1a39be46a9e9843ceed689a85d33092ae50bc0a4726735fde1f645850b6d5936527711bf9b6d93790ae601898bf3ecb8b47d5de65408b167571df74ad193db6923c629bdb9a03f2cb7f6e45b71fbfa84f418cd8f65faa4d262f63226c56ddd9b7678f6742375845ea8361318dae5eb3a4ad32c229f47dcb60910365f9aa93d7a578d6109ad
#TRUST-RSA-SHA256 33b4d848b7e157b6f0ac344466aae538178b70ea1a4fdabcded9090ca973916c52c8d298e221234b30aa5378ce27ac579b621185ed7b6be33e881d6db2ce780df59e85ae443f51ec06843ea88ad0585edd0f044d759b4be9e909910adc2bc9696b63984a0ccbc92565495b6b435477b80e9c87cda6eff78e38ce7cf796c7a677a7892104c855351872081dc4c4fea6552edc96e03bf0962df358b3952ce55612844bc7a996d7d6cb56005235e529aa61beb2deea62a755df2f81ee1e3099661de7c918cf85bce81e116fd87494642f1dd4820f426330705bae5b712d48696badd8074b6527e8c50c1007527711f28b6f7224aaa5d1e6b2fdd063f337ab6bf26060d1dc7e26acce6f8e40c740a719d418e1bd72134da9b72603cdc70a0bda9b1bb46121f39d39c6b59f9b04f696394c4119990da0be8e9ca7ab3232867319191466628146ac0e4579acb568879264ed5f61f55140a57a18c654c02edaf259ba633188042505d4d80d803d9a1cef4049794bfc5981dbad78ddcc1a0c454a19c21bbdc2e91b7ee3df5a3502c0f111b3b767052fe9a54722c3dc071e368647714d0b163b611eaac82728b155a4fafcad10552832bfd3f0ba2740a2af65fde92cb8424398df7ad1a1f65182fe49ec67f6aeaf8240f5317b8df008a9827f88130569a7a325f76082a2bf50e347f85e1564ada523124e263fe9793325ef03d8615b0567
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168023);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2021-1622");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw49029");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cbr8-cops-Vc2ZsJSx");
  script_xref(name:"IAVA", value:"2021-A-0441-S");

  script_name(english:"Cisco IOS XE Software for cBR 8 Converged Broadband Routers Common Open Policy Service Denial of Service (cisco-sa-cbr8-cops-Vc2ZsJSx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software for Cisco cBR-8 Converged Broadband Routers is affected
by a DoS vulnerability in the Common Open Policy Service (COPS). A deadlock condition exists in the COPS packet
processing that could allow allow an unauthenticated, remote attacker to cause resource exhaustion, resulting in a
denial of service (DoS) condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cbr8-cops-Vc2ZsJSx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3f46ab9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw49029");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw49029");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1622");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(833);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var vuln_versions = make_list(
  '3.15.0S',
  '3.15.1S',
  '3.15.1xbS',
  '3.15.2S',
  '3.15.2xbS',
  '3.15.3S',
  '3.16.0S',
  '3.16.1S',
  '3.16.2S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.18.0S',
  '3.18.0SP',
  '3.18.0aS',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.2aSP',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP',
  '16.4.1',
  '16.5.1',
  '16.6.1',
  '16.6.2',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1d',
  '16.8.1e',
  '16.9.1',
  '16.9.1a',
  '16.10.1',
  '16.10.1c',
  '16.10.1d',
  '16.10.1f',
  '16.10.1g',
  '16.12.1',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '17.2.1',
  '17.3.1',
  '17.3.1w',
  '17.3.2'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['cops_enabled'];

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw49029',
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:vuln_versions
);
