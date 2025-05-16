#TRUSTED 7cb03cb4bfe6f3094a18df9469feff0354d594b4bb52aba4c9079ef21ec5a07c6b5828a90b8bbf31dd2cec17811a011b8f6822cc8e596106bf15b738ccf973da634176f0cffaa9959dba26ed43c1a1aeb3921886a073286599d99948ecca70d6d4067a2cf7d7be177663df3cbde5e4dbea53879b07c3f2ee27cd8899803d61571efef4910f1a244a0e5f2066a59138d4592fd61535e3aacfeb9fbf969912d0b7878dec8853d9bc7115149d4ad4834245bdd4e968db029e7d3719cf20de968b659ed1f932291019a419270aff9263ca4b42ebee76a64991cb607f61d8090422969baef23778ad24ae16337b1c85dbd839ed14c826be21eba022ba91f492e21d19e7142da0c3586923be3d3e8ca8942821ca0c4f96fa294b28d8c8d62efd12df24a27389b1eca46a1f50fc4109c101355ea682f1a918eef313341d03b61fc8fb9ce594b2c32191cf7b78cbb6d118717b8169a3f1c106268586acf47f848dd76449aa8c1e547754e960c0e3fd8096468b6f49b4f09163b347e802bf42c1ccb94d9f9ba9e0197799c1e8efe8c969e750cbd3eb5c80d110fc28c87344e2f6cbef1a3ae3193de8b7e6b71feac74502dce9ec5cf1f654398fd2ad38dbd2d5f1c2f79bf58711504de7f35ac7306773640377b380fadacdc4186a92ef3bc4cc6210ff9d45af359eb0d29169f9e4a3c1a34d2bc94968eea7c182d8cd85c34225c320fc876d
#TRUST-RSA-SHA256 a18d09631b8a68292d3e0fcff1b35a145f5cdf7fc2592f11c4c128e23304c042eefecd058082b67730295fe9040460d88c2faa5ccd7e3358a7ac446727e57f140259828471b34a0d08d02b92dd5e67f282e13e1aa1aa2c4f5bc3bf214a86b337593da4a9c22fa8c7ab3c8f7f94374b8aea9304425f891ebfdc02a8d7d690cfda1221fd12a8c2679acdb59f3e5b3e1ba80a1e39597fc383585b3a9aca05221232fd14484194229b7411cc9b0adf1b9b688c52cc8587498aae67d8d8e8e03babd9c2c7c73ec2d43e947edde2a9e7c2a4141421d98bba619956df71a8175c8455449c0ffd38a2cda46659a6a2beb6e77ebd2d6f4b6fe489fa976319154a4ecbc70e45f6ec90e7ebe8aef5af8629b38bdb9f4d2428fa67291ba32dd3f14f0f53d9c619d9d44010682c18ea31287b64c056f5293d6781cdf5083b10104c206b73743edc838aaa962cbe48a5b78f7223c06a546065d0cbc4feabc6999f374fca6a3fd111b54d08e470678888a7a81577e4492d868983ee2f494ef31a66e9c305d0d9c33193b5e88c7a5df3b9eb24ebac8489dd63ab1c01915753e567bd2dfbc7b0e63cb3441bb5c62ab0b8288224b7d0d2e4e2780e05a54048029f5608fb5388f251f5baec65e7993a4885d20a10f17ea0891266cc6efcaaaca303d37d37a6f2815d944edf9bd964ce37ac2e6a120606c8439a52519043e4385072cfbc875b115e555f
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141119);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3417");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs58715");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xbace-OnCEbyS");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Arbitrary Code Execution Vulnerability (cisco-sa-xbace-OnCEbyS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a arbitrary code execution vulnerability,
due to incorrect validations by boot scripts when specific ROM monitor (ROMMON) variables are set. An authenticated,
local attacker could exploit this vulnerability by installing code to a specific directory in the underlying operating
system (OS) and setting a specific ROMMON variable. A successful exploit could allow the attacker to execute persistent
code on the underlying OS. To exploit this vulnerability, the attacker would need access to the root shell on the
device or have physical access to the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xbace-OnCEbyS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?217cd5d2");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs58715");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs58715");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3417");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/02");

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

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
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
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
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
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.1gSP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.2SP',
  '3.18.2aSP',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.18.8aSP'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs58715',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
