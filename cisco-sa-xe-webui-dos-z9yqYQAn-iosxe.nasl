#TRUSTED 5a6c4eb97d59de44bb7fc7c4229dd7d5eba088011a2eb708c72a9774cc8579ed6111902a0f3bd699f3b19812fbf3c1495ee2381ca9632bedb084323826922998678033c3a0082480ed4541a8c97fcb00f1c86fff5a69799fe70652bdefd0646e061c2dfa8bf735377eb94b359515295b9dbe99c9c6cb46b74ffc6199b781eab806e9db69fe9c84747857f9b3034774ea05b55650dc6e301a9a926804bed520838c8202c2d10bd71c18389f3a5e90da98995e0779af3f2e60b697489d098cb5b0552cf6f35b8b8f3ec8b3af97fa3375525fa35668efd8399eaee626cf0bbc2f0b7388c220beda73013ddb67461df40f0fa62d48eba8c7717cc4d733bae4bb5735e57debe9a6cc6129280306d3da0803605ec8857f52ab9cd1fc820b160c6b6493e75f7c52fdfd337bf16022564859143c0e315cbf933648a2ca6d396308d72fc1d2f49b82c9ddbd3370dfedecfd3042f2328618da095634031eb8fddda1ce4e440ac1084259a0d0fad7ab68bb6e5a2cddeb9bc2f278b7ff41c338e272c29676276c93581015858beda1123b3d1d78070f0a36c5abf40d5445e0182af0fa3ae75b7d1e83b2809271dde9b5459187ce1ebb3038d7151b1b950f1ed6e3b50005b260401fbbe06a2a5b0bc22dd67312a25c4fecbce03f4da72aed2efe5a887d20e237cc19039dbae6dbfce26f7f43d5bd100089111dee99f1a20d0314229cc412254d
#TRUST-RSA-SHA256 a337e375a1c7c76266b19429c00383034828664553ea67a31e28cc11a189d4361f39d9e4cd911249a8adadfe28370085ee200391b9b4afb3170a168c974cf13bab88e7071937ee0c49b25d78ed3645e72f20a05d59c6d05b6644844ec23d3977af4e425f690447d0b7edc979112e7219f13020bf1809a755b01c759cf897fd452fb9c4b5df39bb2d92d2f383aca1bb794949d08e061fb41a26cb793725c9437404770596998a6024f4cc46f7ffe1fdb475540a1a2901dcec96f19b72d6b5395faf816d6271b193d3eed5396d3ac5dd3c5740dbdb0186fd6e1edfee4563615e5ce0d85ce8bb6144579e8cc21a5719fb1d85193574e52bd8fca46cca946d50a6d2fe1627af744f6e94d6f0262cd3de6c04a7e968bd64c8962649f5fbd8c951fca6d3d311d4e22bc6bfec679d101ea9d6c3f002e52d25cc44e020d9ff378cbc5f6db0d3eed58f0c393baf05de11a9b88dcfc0c198583f9be9c02912ee69f6ecc6ec8d6ed5dba86e387319b1035d7428bcbad56f21b6597b930bd1f3f7b809085f486c0b328050eecb5ea8d85b27819d8341aec3be0ba7371c5e63f5b671b42a349f0fba29d70ac4f35ac4effa1da9170eb28f49f6b5c1cd3589a83e1291ca2343856360b61e53e2d7eca8a7f9660d5f60f0f4a74561f7d3a3303280a006b40cd09ba022e203d5ebf359fce9d0588979beec7f4b187825cbf68ab42d13f75f5d1d5b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148093);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1220", "CVE-2021-1356");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu94117");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu99729");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xe-webui-dos-z9yqYQAn");

  script_name(english:"Cisco IOS XE Software Web UI Denial of Service (cisco-sa-xe-webui-dos-z9yqYQAn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by multiple vulnerabilities. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xe-webui-dos-z9yqYQAn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5ba9e2b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu94117");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu99729");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu94117, CSCvu99729");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1356");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.15.1xbS',
  '3.15.1xbS',
  '3.15.2xbS',
  '3.15.2xbS',
  '16.11.1',
  '16.11.1',
  '16.11.1a',
  '16.11.1a',
  '16.11.1b',
  '16.11.1b',
  '16.11.1c',
  '16.11.1c',
  '16.11.1s',
  '16.11.1s',
  '16.11.2',
  '16.11.2',
  '16.12.1',
  '16.12.1',
  '16.12.1a',
  '16.12.1a',
  '16.12.1c',
  '16.12.1c',
  '16.12.1s',
  '16.12.1s',
  '16.12.1t',
  '16.12.1t',
  '16.12.1w',
  '16.12.1w',
  '16.12.1x',
  '16.12.1x',
  '16.12.1y',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z',
  '16.12.2',
  '16.12.2',
  '16.12.2a',
  '16.12.2a',
  '16.12.2s',
  '16.12.2s',
  '16.12.2t',
  '16.12.2t',
  '16.12.3',
  '16.12.3',
  '16.12.3a',
  '16.12.3a',
  '16.12.3s',
  '16.12.3s',
  '16.12.4',
  '16.12.4',
  '16.12.4a',
  '16.12.4a',
  '17.1.1',
  '17.1.1',
  '17.1.1a',
  '17.1.1a',
  '17.1.1s',
  '17.1.1s',
  '17.1.1t',
  '17.1.1t',
  '17.1.2',
  '17.1.2',
  '17.2.1',
  '17.2.1',
  '17.2.1a',
  '17.2.1a',
  '17.2.1r',
  '17.2.1r',
  '17.2.1v',
  '17.2.1v',
  '17.2.2',
  '17.2.2',
  '17.2.3',
  '17.2.3'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['HTTP_Server_iosxe']
);

workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvu94117, CSCvu99729',
  'cmds'     , make_list('show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
