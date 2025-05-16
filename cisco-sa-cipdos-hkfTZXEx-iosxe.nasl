#TRUSTED 04bb7e8527d7bf7124cfbbdee22ac8b1a7eacf56dc6531565a55190179774f588d2fe7aa494456e2ec3a1fb7bf54007822d618aee4397c372a75b25ed7a6a4dd7815cb933f323369aa455fe0a4c5317cf21afbc2b7d2c36cc801926c48cda5cba854b2c03e0bd3d59b603f21177e5079db6d1af248ef0c293f901845d4dfb7417cb11aba0b70e6bc782cdaf923d0ac70dc13a2d5511515b3045369bc04afe0ebd0a4a098b6e49e023475032de6543f0c95ad3acb99494f5ad8256211fb4f4254a6f0bc6c0aba69e6cd8b614ac3529c2fa36fb7fc0ea4debebd0029caf7795c6e28663bd5f5c6a9df67253db1653a3234fdd070abb94c2e43d407b13070dd850f0ba32498373c21e721743b7138014a9bc854b84120e79507e82ff033bfa80eacef3315353f0d7376e1dae6c7c307e18e28a38b036235389a5b889f9762e74b7ddbf855d9974fa66a58f46a94f0283bf4ffac4b424407e8434c6ea63fbe7762d0ddc4e44b416d6cee58e8be2e6438e0972d4a9a1840b75591a30da5f65f11384c78e6a613d70487e6202dfee38f9dbfb412405088448c4ca09dbbab73b147539601669035b4f1d9ec2dfa959621855de5fcc97ffa7630486762d4f047c2c49d02e5d3e45e6a38826b97f39a50e4daedb15b87f9dcc0317ee18e193477e351ac666e0bf1f60018be59f073ad8aca0db4d08db128e5c2352ca26ceb7f47aada012d
#TRUST-RSA-SHA256 32c4628ceec6b98e3f4e618683ca089bc16ea8594c6ad86af70b12fbb3918bedb9e088135467d10951d27aa45d258a2bb5cece4f8e154affb559deff22968e1caec00b83014f2e3eeea3ad5e75cd03d3657520a3626af051d24919bde1a455ccad7df31052bc6ea526863da1b9400eec95bd4e3fb8ae715876c80c4affb2718ac953cf060a6ebf7672509b06a6c1184a3919a7380490446294a84ed4c5d6d42a2992ddbf394b341ff6bcc5e933be71179ee166722531c847549d60cc17d00f93f60d6a7a1e2b1aacdd12bc28cbbb596fef3e757ffe5c92914953a5b0fb337f6a8890d77dcca7634fb0fd18117303aca9be79e7eb8c87c966c75bce137ecf5e21a7e4b525b2679a632bc47899b21350d03f90fe7e690729c78623ab130f85ab1b9dc4f4f632607a722c3d5f3b3dfd94d1534acd6a29665857077d2ca4d2cbb69452e4c2ff8b1c1fef34ee881f7c38f5ef859b7b714ead5bb7c398bb2cae171415fed1abe77b29d9a991b65e8719ce971f7424051d1c2576551cca458040746b8702c2874c2e97121ad7960e0c56bf2870ebd496b29b0e4f605e5bfdf9e21abb155cfaefa758443491e9ac8cc9d4b1617011d030d070d5afe20fa1389cb11cd12cb58c679ef97be80ce83df162191415a51494cecef986f2ac2fc0276474230e96813c9e8b8099ae6e308754ac82f8dcaae9d5aad392da56b31736248aa1d56200
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138017);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3225");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo17827");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp56319");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr47365");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr67776");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cipdos-hkfTZXEx");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS and IOS XE Software Common Industrial Protocol Denial of Service (cisco-sa-cipdos-hkfTZXEx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a multiple vulnerabilities in the
implementation of the Common Industrial Protocol (CIP) feature of Cisco IOS Software and Cisco IOS XE Software could
allow an unauthenticated, remote attacker to cause an affected device to reload, resulting in a denial of service (DoS)
condition. The vulnerabilities are due to insufficient input processing of CIP traffic. An attacker could exploit these
vulnerabilities by sending crafted CIP traffic to be processed by an affected device. A successful exploit could allow
the attacker to cause the affected device to reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cipdos-hkfTZXEx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0c4bbf1");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo17827");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp56319");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr47365");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr67776");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvo17827, CSCvp56319, CSCvr47365, CSCvr67776");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3225");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/device_model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# Affects 4000, 2000 Series and Cisco Catalyst 3900
if ((model !~ '[42][0-9][0-9][0-9]') &&
  ('cat' >!< tolower(device_model) || model !~ '3900'))
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '3.8.9E',
  '3.8.10E',
  '3.6.5bE',
  '3.3.2XO',
  '3.3.1XO',
  '3.3.0XO',
  '3.10.3E',
  '16.9.5f',
  '16.9.5',
  '16.9.4c',
  '16.9.4',
  '16.9.1d',
  '16.9.1',
  '16.6.8',
  '16.6.7a',
  '16.6.7',
  '16.3.9',
  '16.3.10',
  '16.12.1w',
  '16.12.1t',
  '16.12.1s',
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.3',
  '16.10.2',
  '16.10.1g',
  '16.10.1e',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['cip_enabled']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo17827, CSCvp56319, CSCvr47365, CSCvr67776',
  'cmds'     , make_list('show running-config', 'show cip status')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_versions:version_list
);
