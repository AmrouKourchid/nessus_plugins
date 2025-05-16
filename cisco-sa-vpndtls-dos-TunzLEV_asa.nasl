#TRUSTED 06f723a78e51999273374ec94d7d1140ff18a1953320ac6ddb2c3bb9f2b07e77964a6d06b727c59db1822266f4720da0994070ac659d9f6152d711a5dd0c5735375f94f5539ec0852cad3bf399700667a349199c6253716dbac1b5926f0435769db547b7ba802a1d08968750ec981c2552a030ac4fb817ce631be097b95420af8ce80210d373672bd34adcf7c53b96442c7e39a1eb5d64d514a28d87d5cb531cdb56d833f5bfb22c6bc95abab68b606e899e6309a72524c5992e74d1c05fb41befa1df543c9c2ba850d24d027809507e2b8b5d793d3310b02e3a10bb772a2d74687b2894f76de6fea30c509f32b93aba7c3cde340e77b7872963a9ba2fdd84cc19324e89c5ba4ae72a60f9406fe030bb8957f0d1814fdfe24efd9ec93eccd0c854d16d315e8e0cb9097ce2cf7e064e435f879f2d8ca7e82781294d978cc90c6f7c88eec49278eb5b43e022a02a4175a8b620d6a7ea46439514712990987fbb745c61e82aca0e5e1a10f0e12828316a24734f15ae3a5f8551f69500f765f200e9a673b42648c3debcab9a3891858d34839c8024765d22ffdbab88fca1a6a8239b570fd4dcd4e82305edc334d2719f8da5dfc94dedf9902db43a3345467c6fb8e5d71066aa93bee26a839607e90e81f65d2af5640e385dac480653da0a3120c661cab611f6698ff8351e603a306f69d253063c13f86d596559c6549b24dfabd5f5
#TRUST-RSA-SHA256 711c963038f2832882789f5937f78ced9b6bc66f5b3301a046117349683d49aa808e68dbceeb5e185bafd55f094bf0ca3fbf9bfef361a715632a02abf2a8c5a9061bd28b0930293e6ff6ee8d045d608694581b607b16351434b876fce450335c4c35afc545b47c4bb93b0a82fdd5811278886107e45ac43a768ac9a2ca0ca1973ad757e8b3b02782a9247a0dc25cdc4bb52b4b531ef77154101ceb1430293d7c70378c966abad69fdbe1725b64359efeeab40a955f6feaa2af2c065fb1a0accab0597f55df149b774cc45b8f59db81b4ca9295e16504a60404b4b4bee252c3a201bc109fa872c790d4a11fb8371712c62112f5e1832fefc67b54b5325e13d6619a23951c620137cd6d84490483112630f6a2b7a1e4087cf9b152c50870b4ecdec39377d8d711c8eafe81e6f9c9936544a463854fa430810c24ed2e77bfcf73d24e3eb0677fc4e9b8518eb2809c80be7cc6a23729271ab62a833abeae62547ce46546480acb81126c3b084595511c72c108e92a78e74bb5d29e770b50cf1f552178ef63db7cba0828d7d2e396d3f28717dc8dd70860083845760e723c2a39551c4749a7f7d768ef875eb82605ce9d664d91e535891f8ae0ea4d54b17c570a63ab8cb2fb4f7edeedc0109a3e8699eff23d7ccd6122ab32eb6fc9ff76e94bee5e008bd8bf36caaf384d4d56707533e1e68215dab677bf3891f5099fbc43d3527558
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160305);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/30");

  script_cve_id("CVE-2022-20795");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz09106");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vpndtls-dos-TunzLEV");
  script_xref(name:"IAVA", value:"2022-A-0180");

  script_name(english:"Cisco Adaptive Security Appliance Software AnyConnect SSL VPN DoS (cisco-sa-vpndtls-dos-TunzLEV)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a vulnerability in the implementation of the
Datagram TLS (DTLS) protocol that could allow an unauthenticated, remote attacker to cause high CPU utilization,
resulting in a denial of service (DoS) condition. This vulnerability is due to suboptimal processing that occurs when
establishing a DTLS tunnel as part of an AnyConnect SSL VPN connection. An attacker could exploit this vulnerability by
sending a steady stream of crafted DTLS traffic to an affected device. A successful exploit could allow the attacker to
exhaust resources on the affected VPN headend device. This could cause existing DTLS tunnels to stop passing traffic and
prevent new DTLS tunnels from establishing, resulting in a DoS condition. Note: When the attack traffic stops, the
device recovers gracefully.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vpndtls-dos-TunzLEV
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?864a3e06");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz09106");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz09106");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20795");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'max_version': '9.7.9999', 'fix_ver': '9.12.4.41'},
  {'min_ver': '9.8', 'fix_ver': '9.8.4.44'}, # https://quickview.cloudapps.cisco.com/quickview/bug/CSCvz09106
  {'min_ver': '9.9', 'fix_ver': '9.12.4.41'},
  {'min_ver': '9.13', 'fix_ver': '9.14.4.8'},
  {'min_ver': '9.15', 'fix_ver': '9.16.3.3'},
  {'min_ver': '9.17', 'fix_ver': '9.17.1.10'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['show_asp_table_dtls'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvz09106',
  'cmds' , make_list('show asp table socket'),
  'fix', 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
