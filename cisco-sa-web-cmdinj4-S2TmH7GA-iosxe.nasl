#TRUSTED 974b4ef1fa393f36449de78b38331196554127eff3b37246a6707c6f27912173926bc1fbd0e4827f21bbad19700943b7050a2260a4bce13dfe1d22be5445ef5d0fc1e4b080cb0ec5f15735b727f9694992191c401516149a850dd6721172c9c4d71658007b892471e1a2a22ca35ba8010aa1fe286c5e57222e98ed40d569b7bef5793513bbc0bf23928b93a26a12d5c3e8d420153e94c3c2e154662bbb2af785d90d5799fc24ab27246ca4c032a908e0ce8a458bb105af1772b7b37f8366fa9f0eae5921c15a5c1d234cef06d9152502f0a83c6dce1d1380dee07b15d152682ced1f53d944c7eaba836ebb59c84aee6b5d67f9a07402b2ddc23955961310b8546914bb739aeb0e2a15cd7dca68ce024ae3be30d85879e647b4915838f1c1fe51f079d15f50d5e5102ff2bd2d07c671e6e1e1690ca062f9832d7d882affcc56dc1831c849d4ec651b049342674a734c78277715fbd7c513d51e5d20d1507ecf6f7be623fbce4cea73a21eaef477071fb2329b188e83a77261faa8fcc627156ac6c8e4f43dfdcfbf58c1664f2e202b0786ec9167f3755c09b1b682bf4e4e52b87f561f4f7b193f9be04a2a7107f5e903187a923ee72deb88d8f26733aa3bddc70dcb84923d4804a3080d65ba518233ea72c3f3c228e690aa8d0d1aca073bb325f9543b8138146afac8cb7180b682416b68a7abafc75f34cb491078ba24baf1c681
#TRUST-RSA-SHA256 8585f75fe368aed80375d7cd2795538e9a08c5e7ce398deceb9a24a294ca9e00bae64d9eac29737974f7564cf3a0df58d6ffd5cdfa4666c8106968fe843e2279abc286a4e5f0f93a5d48f18f7a660253a76da06a71a54531cfc58764eb5fddfc80053874a5a43d2380855c18257aa2ad2a2862464b5d198d3bbb7396ff793bbda3c41b99e2b1fa290333aa87e166b7a5bf8dd1004a327f3457b5a3ed4c66c59db046511c1a396855752d794ccc4701c343e90ee71ec99e48b9b85b4ee0ce17a383e30d8bb8c9030c18f7012f83b8facec41e215824ae3e955ee4632bf735dbab8d1106f268218b031b2c0b949335b2da31626b5466e2e6d6a85aea678c97570b9d41958b83275d42240481552bab3064c7e78352435ab23cee86b565245221d31edfb1d02e77693ba2374e1c539d9fcced3d0b048f56c066e31972c080f7386486dbf47c2636faacabf7c04bddd9fec14f1b72f3b5c10be9ceb9be9771fb8743d0347cfa4364e6042046fb7cab8af5a652b4ca39a6f4855e9db5b6d8d801427cd08bb58eca72be10494aeb81337d25ed21eb5e0e5706cc146c4553809bd0a140e2199887b6bbee7d0a3daf297166d74f258209e2c319057aa34239262540e86abf13b71ea7bc365f291c672978c593ca5233f76e00b0016850b832a5f15dc834cfe32feae4adf2cb97f9158c462753aa0f9a976cb984b37c2658538b0fc6336f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137185);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3211");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq32617");
  script_xref(name:"CISCO-SA", value:"cisco-sa-web-cmdinj4-S2TmH7GA");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection Vulnerability (cisco-sa-web-cmdinj4-S2TmH7GA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-web-cmdinj4-S2TmH7GA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee496248");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq32617");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq32617");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3211");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_list=make_list(
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
  '16.10.2',
  '16.10.1s',
  '16.10.1e',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {'no_active_sessions' : 1};


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvq32617'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_list,
  workarounds:workarounds, 
  workaround_params:workaround_params
);