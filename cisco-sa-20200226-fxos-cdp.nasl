#TRUSTED a5ba10b74e06649dd22d6f72f1b0322c57e76315673373ddfde1b15d70d9fc45e6669fe8e984edd8e8f4d4a9f7aa496d8038354af02679f4830bd98bc98f4b46c2ca3b72650fcc5071d836543654fa74123000d86513b4cecadc66eacd6eef674fe0a8c1969823b6eac352b0b87b9195d820c8d9d8575c59b5261642d85e21a2023d1b671f11272a5bf665ba61e6114bd65457d9b86f19757759f0b999c72ce9d70064dd46a6928a7d0a47ec38418348271505ee09c6889a07d4dff8cdd2557742bf670749352d6f4dbe010ce329e1f721da50c53d50ea337926714ef970e6b8b53635d75d03bfec49e1924925f3da43d21a35fd2779752e236649bdfb1850d473e59f2615d1d32bd55ede2142c4ed1616b8e75bfd4ad5443aee160290791046fdea96eab314f1c782e1a4d415b3ee3b026a76a8fee87178185e3b8bce64682ee83ee62fc10b8e606cc229302af34fcd9038caabe4701a46f4091ed2b78257c2e06f82236ccd333414280fde0e769f18894f30c24c42d6ecca60567123fa9b76dc78a842c754142cb351518388e6c276377dd99f573a6d936b16bbf550be7c6ecf3e231ea5e3805933a7f318b22b4ecca41062b83d7401bc3aec0a5661f7022982b4b0d7ff62456f43db939a152331ced636b3cf65478b60267e5fcfe1316b56d3d3ae2bfcbc5a481c383bf74f4464e3d2757fb83ed3c27e2c1c14479f2f272d
#TRUST-RSA-SHA256 330d30c2ec67358b0124b66fa6657313ad78aa5fd252fbc85b754a549c404193b83f8dcba6f78bfd0267564093870ec016f30020500cc0377957bd6fce511fa47bc809720d2bc3e9bcd18f34c692969bfe60191d000cb1036a1e96288b85e3465b61d1a533229e45e77dac58a2bcb52931a180019c532c736fd7bce428b246cb9c3d6d6d385c0c0234733d2bcf2556bd7e0633e8960584bad06bfc6cdbf981fa642ae4e380c582d2706cf365ca5f9ba909490bcd406ed8acd808178b53f4e91e482242e17c5368cc1279122023830a7e810f606a09a5c569cb1e37e1f16f31403333ed5c6b18e0ea973b159a2c2af25e393d11ac796ba1a932ec2a2bd20508d2d0d0f2df39a33372155f091d60a3d3e27b9cba281703979139ca26b1d80be861e7b7b703811919e454cb38f1f3895a8a208f025dd6eda4056ad7c7dfc05c1b94372f88b409e4e41c48b7eadcba067a55ceebe59f742a95c5980c753423e9d88fe958e66442bcfd0b395da38eb00f02e518380c95e711d70730291d7ceb16749ee096f4aa22d69a210b215b0bbf08418e46e22cf74dbfdb62a94901e3a377f2801481d7a6c26cb2439ac0b6fa554d6ad0600fe5746b3a23a480c7650d4eea94e7afe4c3731c2b897aebd9e9adf31f9454312cc387e78c89b452353f71b6c566bfb6635d437aeddb009b802b4b16db715bf6748a748b341f015c4bf3e73230be63
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134234);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2020-3172");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr37151");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-fxos-nxos-cdp");
  script_xref(name:"IAVA", value:"2020-A-0086-S");

  script_name(english:"Cisco FXOS Software Cisco Discovery Protocol Arbitrary Code Execution and DoS (cisco-sa-20200226-fxos-nxos-cdp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by a vulnerability in the Cisco Discovery
Protocol feature due to insufficient validation of Cisco Discovery Protocol packet headers. An unauthenticated, adjacent
attacker can exploit this, by sending a crafted Cisco Discovery Protocol packet to a Layer-2 adjacent affected device,
in order to execute arbitrary code as root or cause a denial of service DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be9c7431/");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr37151");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr37151.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3172");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');
product_info['model'] = product_info['Model'];

if(
  isnull(product_info['model']) ||
  product_info['model'] !~ "^(41|93)[0-9]{2}"
)
  audit(AUDIT_HOST_NOT, 'affected');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.6.1.187'},
  {'min_ver' : '2.7',  'fix_ver': '2.7.1.106'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr37151',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
