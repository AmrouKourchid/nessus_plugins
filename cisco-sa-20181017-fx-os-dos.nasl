#TRUSTED 53167f4654e5ca8129dc10ac277b9083bfdabf070e101eb3d794c70204f01bdd37497147b1ecf1bc726f815a3710a450e4c69470c8abe2b942bce677d31d7882a0c38034f1a73525d4d020c421dfa4f8ea2f76b98e546fa23c0857f112cca4ac7d821ce0cb80d82ae21d69759a99369e20a9fd01585cd3ff9a829c5f8cd2f3ef0f897530b0790bf9a89e1e3010f18d9d89ada5332628a7be5aaf948ed063638840518d2d3a0635e733219d0bba965bcf1bc6b49cbc0d5e62065510b833be0fed4909908e9e6e814565caf9f9228d09c49f81c58cb2ba91d0ce83369fc6a2568cc75d8a2e878992c703641aa19d7e8942a68a79591bdd861d6f48060c1b4a747440f93872f691b27ebb3bd7937a4f93b7dcc0605e9464a4e1fea637873ee1376fb7e185af79909c9741edf88574d4ff786b1821f3be267eb0809aff435d5b088491442d4cf9472eae2e99bb2367fe92820d3e5d22f411e985907b0ca375fbf293a5b401038d5869160422610e03f8b5815a5cfad420683997d6bf7b632e6eafa496c52518c577046ee4c64bc2b6548f33faa5968b221c23b39d91a90b5e9302d9ba033a832b6e5bce4d2f0cb23b978374a7f0b5356a99791b2e2b20c5c1cf79dfd8ba5a7ba82e2ffb8b687dea53f98bb42baf28334f7a969c872a8c247b315f66c3e6c9224f607a65aa96de1f9edcf37fa1d7e8c58d4bda18dc465c1a15196ff2
#TRUST-RSA-SHA256 58238b93c801af46542415fa68072f18ed312200d713f43a91614b544b68c7fcd999e57fb96d74e5fdf0203142fc594f66f26de5ae61015030fe49be4b2b7ecb60b4e4ca34f37333a338192b209c9fc0e7ab0ae2922b39ce47e38be47fe1eaeabc83acef7b8ea5e6ad1595ea5b73597a9f6b38307e7f872176354633fe2d6311436532df35cfe10cf29d2c14b356207d3b3e47749226189a6f4bf99ebfb4d738630690f5479068f640d40b9f1c587c3b7b3bfc5338d286c488a03676e003caac0a236511d2eaeaa101270082f43a2da263448e2c33149f4f200920696e72721a478c6d0079c0c0ce741b1cc0158720a9e1eaa6c478d11070fbcdce15b5af278984fac893018517f946312ce61c9a6fdb24a47ac59cf3481962273f8a53d1caf94f6e282771658fdb3d58b70f2e2d36e77f563eccbd95f628ad7328e2f9921833cc0250957dc70c32959a4966ae30fd369a4ccb4ff72f908c033245d4c056c820126cb4d7051d86df9d196cea4a6fa5fed6f2d32e1f1de53ad2d34a69ddfc7265fed5b1a0c951a47209a4dccbcf2fbff1d28817e037c44d178b8ac71b38e18ff15cb9c37057e472638fc78b0d6e04a340ecfc32e9ed222dfd0a1f30e4dafd503631ac79a659ed278bf7d634d2dc99498cbe7589f6442904accb3c5908c748404ead98ac78d93bbbb93204d60f6417a29cb8fce8d636977b6c4c9582e36721077c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134946);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2018-0395");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf23367");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-fxnx-os-dos");

  script_name(english:"Cisco FXOS Software Link Layer Discovery Protocol DoS (cisco-sa-20181017-fxnx-os-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco FX-OS Software due to improper input validation of
certain type, length, value (TLV) fields of the LLDP frame header. An unauthenticated, local attacker can exploit this
issue, by sending a crafted LLDP packet to an interface on the targeted device, to cause the system to reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181017-fxnx-os-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3775192a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf23367");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvf23367");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0395");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');

# check if 4100 series or 9300 series appliance
if (product_info['model'] =~ "^(41|93)[0-9]{2}$")
{
  vuln_ranges = [ {'min_ver' : '0.0', 'fix_ver' : '2.3'} ];
}
else
{
  audit(AUDIT_HOST_NOT, "a vulnerable model");
}

if (report_paranoia < 2) audit(AUDIT_PARANOID);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = [];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , "CSCvf23367",
  'version'  , product_info['version'],
  'fix'      , '2.3.1.58'
);

cisco::check_and_report(product_info:product_info,
  workarounds       : workarounds,
  workaround_params : workaround_params,
  reporting         : reporting,
  vuln_ranges       : vuln_ranges
);
