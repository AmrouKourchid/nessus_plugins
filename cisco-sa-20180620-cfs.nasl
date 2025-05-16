#TRUSTED 1dd18da134a5d5c891c1fe654d5d657cd8cb29a802f80809704ba3d19dda233cb215014ba906cc103b7bd50c22f08248f14079e928c44f4a8e4009d5474fea75c73f2d30a652b8076c9c9914eb68e8c819e238dd318f05ea22039ff7b14d6661fc6321d29505ecdf876460400e2fd295ea415341ff1c7b299b54850b9fa86b6d611824934818289b1c1ae5edb193ba92647f1d3831ea51bfb637d19b63895ed866879753c53cf976f072d028b0575d570198487a3f3dad9f249323c584faee1d5ae1b1b820c0e2d0d1e07f12dea11f9ccfe4e211ca28839fb17787b217461d77a9bfec4bb23b73e567cde5b079ed57c29175fc8cf048360e8a91331140f449b2353253e026489ab2fea977dcc2bbf7e12c2b5b502290677d0709a8e1c162eafdba4e2e9ae9b33b027c37fe6cf2cdae90dbfb8397006870fde0ec94b91b3c82753c07f8c294c0e996e2ba370eda9462c4f95e8b4771e842a0a57e8cce2f35c8ded1be4a5e004045b8fd4ad5915cd6a14b9635e2ab8dd754beadb7d69cc02d2323c56229603d19e465b9b7012757641e26173b758f7d7c6f5f847d99659ebb9f5777d7bcf6fac0a3fd7058d1b693579ed50d659a4ccb5abf41058a65358c9747a1a8efd9d6cd6d730f877acf853578ab3ee7388ac068509012c1068c89fb733f4a56a63c9e378f15b60ef817cf1f2207455e812ad0ec9f51a657b382d56fc4859e
#TRUST-RSA-SHA256 00360224174f65c695533191453cff1f88f5638ce9cf2cf5accd41c28aa3f19d8da8571c948cd1a0b998dd3c87fb04783ac559656f343599276e7e5f87c125c62da80552c4ace63e4e8cad21ca2bdb8be1c2e878cd1fba37a64992b4a14b2a567a1a70b03dcf3cd1c3a0064a475d5986d1aae012fa8ae6fcb3a060fb80e0f69aa738c360e9faaf9574b9af03ad2832a4cc787f861ae4ae658d0a4c6d66667d38c193ecbe8fd9405c8bedf77d8afce9163f0b593075e6e7b525ca457d17fdd8cf3fc824ed26de667d2b03015396e1917752c03a6604388d04f76e11dd057ebca7174cf7e74863bc6d98536ba4cbac91efb395cc691f76b1014d4146a57f0a3053951fbf20386e0274e0283cc555eb82494f6596e06d5b3f4df8d646c2b77511d175bf7f67f7d9577041f7d4147ffaaf827c5907f26e02d8e8cbd7718df685096c8af9abf8d4be9799de99d31cf71d1c7f238bddbb2d9345ca257c2c3daab4609e9880cb8cce4f8217277c0becd555fe2a9772e73f11b57340a56a362ee2063e44c7536994f743f352449921877d1ca8e321a3ce668d439f01e5fa96cd24dede4f18f0a1434d7b32e016bf974bf6ad93fbffe48ee01572397ebf19195589deaec26ceda89cf84e750fa97ab7431fd296deaaad7706626a10cef39645a5dc2022209e5d9cdab6b7867ea31e634ce0e9fcae2cb78a5b20cd6281f19a5d1c8f3feef0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(110687);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/16");

  script_cve_id(
    "CVE-2018-0304",
    "CVE-2018-0305",
    "CVE-2018-0308",
    "CVE-2018-0310",
    "CVE-2018-0311",
    "CVE-2018-0312",
    "CVE-2018-0314"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69943");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69951");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69954");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69957");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69960");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69962");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd69966");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02429");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02433");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02435");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02445");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02459");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02461");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02463");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02474");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02785");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02787");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02804");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02808");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02810");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02812");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02819");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02822");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02831");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve04859");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41530");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41536");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41537");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41538");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41541");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41557");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41559");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41590");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41593");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41601");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-fxnxos-fab-ace");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-fxnxos-ace");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-fx-os-fabric-execution");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-fx-os-cli-execution");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nx-os-fabric-services-dos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nx-os-fabric-dos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-fx-os-fabric-dos");

  script_name(english:"Cisco NX-OS Cisco Fabric Services Multiple Vulnerabilities.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software is
affected by one or more vulnerabilities. Please see the included Cisco
BIDs and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-fxnxos-fab-ace
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6219c29b");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-fxnxos-ace
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?267dc032");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-fx-os-fabric-execution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?217b85b2");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-fx-os-cli-execution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0884367f");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nx-os-fabric-services-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a5a1307");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nx-os-fabric-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f589839d");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-fx-os-fabric-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33153cf4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69943");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69951");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69954");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69957");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69960");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69962");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd69966");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02429");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02433");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02435");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02445");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02459");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02461");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02463");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02474");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02785");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02787");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02804");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02808");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02810");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02812");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02819");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02822");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02831");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve04859");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41530");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41536");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41537");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41538");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41541");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41557");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41559");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41590");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41593");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41601");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed / recommended version referenced in Cisco Security
Advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0310");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-0314");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

vunl_range = make_array();
bugIDs = NULL;

if (('MDS' >< product_info['device']) && (product_info['model'] =~ '^9[0-9][0-9][0-9]'))
{
  vuln_range = [{ 'min_ver' : '5.2', 'fix_ver' : '6.2(21)' },
                { 'min_ver' : '7.3', 'fix_ver' : '8.1(1a)' }];
  bugIDs = "CSCvd69954, CSCvd69951, CSCvd69943, CSCvd69962, CSCvd69960, CSCvd69957, CSCvd69966";
}
else if ('Nexus' >< product_info['device'])
{
  if (product_info['model'] =~ '^30[0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '0',        'fix_ver' : '7.0(3)I4(8)' },
                  { 'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(4)' }];
    bugIDs = "CSCve02785, CSCve02459, CSCve02429, CSCve02810, CSCve41537, CSCve41536, CSCve41590";
  }
  else if (product_info['model'] =~ '^35[0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '6.0', 'fix_ver' : '7.0(3)I7(4)' }];
    bugIDs = "CSCve02785, CSCve02459, CSCve02429, CSCve02808, CSCve41530, CSCve41536, CSCve41590";
  }
  else if (product_info['model'] =~ '^2[0-9][0-9][0-9]' ||
           product_info['model'] =~ '^5[56][0-9][0-9]'  ||
           product_info['model'] =~ '^6[0-9][0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '0', 'fix_ver' : '7.3(3)N1(1)' }];
    bugIDs = "CSCve02463, CSCve02435, CSCve02822, CSCve02463";
  }
  else if (product_info['model'] =~ '^7[07][0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '6.2', 'fix_ver' : '6.2(20)' },
                  { 'min_ver' : '7.2', 'fix_ver' : '7.3(2)D1(1)' },
                  { 'min_ver' : '8.0', 'fix_ver' : '8.1(2)' }];
    bugIDs = "CSCvd69954, CSCvd69951, CSCvd69943, CSCvd69962, CSCvd69960, CSCvd69957, CSCvd69966";
  }
  else if (product_info['model'] =~ '^9[0-4][0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '0',        'fix_ver' : '7.0(3)I4(8)' },
                  { 'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(4)' }];
    bugIDs = "CSCve02785, CSCve02459, CSCve02429, CSCve02812, CSCve41537, CSCve41536, CSCve41590";
  }
  else if (product_info['model'] =~ '^9[5-9][0-9][0-9]')
  {
    vuln_range = [{ 'min_ver' : '7.0', 'fix_ver' : '7.0(3)F3(1)' }];
    bugIDs = "CSCve02804, CSCve02474, CSCve02445, CSCve02831, CSCve41557, CSCve41559, CSCve41601";
  }
}

if (isnull(vuln_range) || isnull(bugIDs)) audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['cfs_enabled']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , bugIDs
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_range);
