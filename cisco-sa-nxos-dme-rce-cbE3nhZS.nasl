#TRUSTED 64fa5f0868f1dcd3062023a2ebd0aabeb1d4fad8bd08090fadfd1903a29374b38a4a27cf3a504d2ceb38e20a2aacb12c07cc59f1af38cbba34a2941dda2f37bac494667ed8dd74d7f989552dcc3730e50df610769a95da53cbfa1c12db4576cf0348c32cebb88820db93396ff529c2a76240c2eb4fdbd301dec28710fe82e19292aa6bfa35aa0f92ea07f2cdda3ff412700dba4f1b74d575594a0de2420d2dbfe03bc9be70e491ca3cdb1f2c35cfae8e934a70323594d544e659d577a9e32f4f25cddbb2ce1bda87e932f342fefae58a169aa169df539b4cd6c2f04f95d6830d00e9bd20dddec5cd6d6d0786435bab18e618fea526ec3a5f512982d459acfcf112cf76e906c5298bdf4eb5500ca58d12fbf8a62a65dad0595b533eecf5257107527f379f6815d7ec5deaf8470fd00f2de3a1818f13cbcb8dc13952ebd9a171d2532c5f46cc8610e22f1c5003682a789054716cd2c06b3d407dd142683520ff340df52f3550f1917bcb39c84514bb1364d9c9d5324de9adf0e16c0f3bb2ab7b5aafe22a8fe0acb811c47fabc2ba57149f2b1290d64ae4ca52336f88e0bccc1b49093eec099088d5e23497b489a255e383cc9ecded106f1e34894ba631f4385f9d1ffb3fc3fb5e61f1e87d01b89bf738a4fbd9738a311fea81c9d54e185113d5d8605db087d252fdf3f289f0418a7c8019ab8e231b3af10943673e781d190a88ef
#TRUST-RSA-SHA256 05e3d44a81e2dbd822f695522735b3163696c8cef768a493549b9b2c1457c9db02c7c7a086b91631de0fd12f60c7f631395e658e8d583e35552991ac73a652ba9dc8e65155bdeb6bccf470109ec414123f093572e977dddc6bade4d1896ae43333c84307e8a1032f0a2d568080838edf0d23b04df0439759d58d9bb1ec39a8bef05abb4ee38108d652e84034e1860a4c2c2ceadddf14697f0e4bcaf8674180fe0090a522ab268563a312de5d60a90a0d5db37d1195a1169667af414e9fa1098b4e0d924dc6d172e59d2bff4702573e77587aee04d259916c018b8cf6a8ead6f4f75ed7192230a4deaa7d99c338f4656a276e3583adc33bd5cf9538878396a8bf59118b30242823afa80707f1566d3143ee5064aee52311fa3bf32aef5f5e6fe76f9173cf2064af9da7e2034ce86ea07e381dd5fdf9b94700b74fdededfa55a941d0755b0e61d2a76f3fad0cd535883798ed2cb09a8d16a8a941fd23aa4caff190970fa0b4bc6603f13264566932992a6494ead22b56a33aebfda22e52cb748b4af57dd54b2886de98022aa2f4d5f6859733ea7bcadc68858e1fbd3fb3e6c4510a947e5cae01fc355fc138fe5a9a7d9daa1b8f555e2c071a18a1b8ad995b99772ba37209f78e765167a6240051297e5a04f74c2397b23f61a5e821ef7d29a4eb9f560efff7de8ac3a8c4cc09e3ffb6dd8430fa4857ff7259da3b41a8d88e11eac
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140185);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2020-3415");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr89315");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-dme-rce-cbE3nhZS");
  script_xref(name:"IAVA", value:"2020-A-0394-S");

  script_name(english:"Cisco NX-OS Software Data Management Engine Remote Code Execution (cisco-sa-nxos-dme-rce-cbE3nhZS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a remote code execution vulnerability. The
vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability by sending a
crafted Cisco Discovery Protocol packet to a Layer 2-adjacent affected device. A successful exploit could allow the
attacker to execute arbitrary code with administrative privileges or cause the Cisco Discovery Protocol process to
crash and restart multiple times, causing the affected device to reload and resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-dme-rce-cbE3nhZS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f83e12a0");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr89315");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr89315");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3415");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
cbi = '';

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ "^9[0-9]{3}")
  {
    cbi = 'CSCvr89315';
    version_list = make_list(
      '7.0(3)F1(1)',
      '7.0(3)F2(1)',
      '7.0(3)F2(2)',
      '7.0(3)F3(1)',
      '7.0(3)F3(3)',
      '7.0(3)F3(3a)',
      '7.0(3)F3(4)',
      '7.0(3)F3(3c)',
      '7.0(3)I5(1)',
      '7.0(3)I5(2)',
      '7.0(3)I5(3)',
      '7.0(3)I5(3a)',
      '7.0(3)I5(3b)',
      '7.0(3)I6(1)',
      '7.0(3)I6(2)',
      '7.0(3)I7(1)',
      '7.0(3)I7(2)',
      '7.0(3)I7(3)',
      '7.0(3)I7(4)',
      '7.0(3)I7(5)',
      '7.0(3)I7(5a)',
      '7.0(3)I7(3z)',
      '7.0(3)I7(6)',
      '7.0(3)I7(7)',
      '9.2(1)',
      '9.2(2)',
      '7.0(3)IA7(1)',
      '7.0(3)IA7(2)'
    );

    workarounds = make_list(
      CISCO_WORKAROUNDS['nxos_cdp'],
      CISCO_WORKAROUNDS['nxos_jumbo_frames_enabled']
    );
  }
  else if (product_info.model =~ "^3[0-9]{3}")
  {
    cbi = 'CSCvr89315';
    version_list = make_list(
      '7.0(3)F3(1)',
      '7.0(3)F3(2)',
      '7.0(3)F3(3)',
      '7.0(3)F3(3a)',
      '7.0(3)F3(4)',
      '7.0(3)F3(3c)',
      '7.0(3)F3(5)',
      '7.0(3)I5(1)',
      '7.0(3)I5(2)',
      '7.0(3)I5(3)',
      '7.0(3)I5(3a)',
      '7.0(3)I5(3b)',
      '7.0(3)I6(1)',
      '7.0(3)I6(2)',
      '7.0(3)I7(1)',
      '7.0(3)I7(2)',
      '7.0(3)I7(3)',
      '7.0(3)I7(4)',
      '7.0(3)I7(5)',
      '7.0(3)I7(5a)',
      '7.0(3)I7(3z)',
      '7.0(3)I7(6)',
      '7.0(3)I7(6z)',
      '7.0(3)I7(7)',
      '9.2(1)', 
      '9.2(2)',
      '9.2(2t)', 
      '9.2(2v)', 
      '7.0(3)IM7(2)'
    );

    workarounds = make_list(
      CISCO_WORKAROUNDS['nxos_cdp'],
      CISCO_WORKAROUNDS['nxos_dme_enabled'],
      CISCO_WORKAROUNDS['nxos_jumbo_frames_enabled']
    );
  }
}

if (empty_or_null(cbi)) audit(AUDIT_HOST_NOT, 'an affected model');

workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , cbi,
  'cmds'     , make_list('show running-config', 'show version', 'show policy-map system type network-qos')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE,
  require_all_workarounds:TRUE
);

