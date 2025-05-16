#TRUSTED 31e586495c2cfd57686529e25345fe12fd093d8df7a29f8614d474bf4565f848b2d7e6cfe62c7817092910328992a4e0204521ffd21b99c0163028bebc34e61b37ba376068580d7f2bfa4d121c70addf8ccfd49ef7496c908e0dec27bbae72f4b6953293c69709a240e798fbfa3138e03a0e496e68222c0669dfeb2193b9998cd47ecad8b98f37ab5070fed07e6073ad4e67d2fb57215e1b71e8515faf566c7ef22beed264f140b87d86ab7da60bc7dd210322c59288b611c7e803f4ea01dd87e083186a2cb87060bb17ede6f1d6936a41be56bd44acb50db4346547bd343005f8363c705af7513ff32ef92d13029310d991c9c9a42f1d2d4e855be4f20dd7b8cd1a62f869571a3a57de596d89ab4b337c8dae849beb1ca16366efa9d36efa0ff9c2419f6166b1211cc1ba831d67c403117234c463ba758a2db4fc9158e713d5255e5c9e8e95188f8bdeeb3ced94a92157c393a6ceba6dd4885a83e5f5e3910b17afe3e3f17b016841d1e479947a07f682b8f6d8376041329fe461c581a0ab82cb7f4b4b5ac5e7ec6e2103a934144ee2c52188af6c463b1d6a148d3502ab8c8ea30e6937f0a90e8f77b0c095b1c6535edb6c94a71c7e621b0586694ba1dff9e56c52af4cf06f8843b2db8af433fd48719f2f5ec79bf83e8e33883aac2bf46fa4c773f7939345dde530615e9975c6d72ff005a4e0cf87679b7c5e2e6b645eb2c6
#TRUST-RSA-SHA256 ab7c4d4c9d674f93e0fdde406875ed4a3fe764afdb8f0963831691e8d5b03c9d8fb0f5762e624eac772c86f740e5d8a97a9809b9c0907330af4614bebefbc7a39f18f6b97fdd7e90aa05d7231e17c65cb29fb4e5bb0cfc3c4204169479eb5a123094288a3002429478167ac7745bed8a6a0d9eaabe53a3bb4821b198f118323fadd5643cf5716ee79f6741c203b3b9c68ba22fa15da60cd5630647dcd9d5d8d95eb6c32e71c4a07e696307093e58aed009e35464f539be67d4192af06080b29917dae9980abdcb6a256c66279c117efd0e89257a5b33c205fb541a9c24136162f4eba7fbbdc70e5306d74a20e8177a5ce2d4d58b4e710fcfb6031ade4f0cf4e9f3878819092b080630fc4b439ab6d384f57f3135f79e2580209e6ba3ac4c1492a98993a88c467ba5310c0d3ab50bd577eeb1e64dfc6780d918746bb3622feec2579562e0c231c0659c3766a4b2f58185c40e90a60bdf21c0aafde7a299f8a0193ebe32f73e6fb06230928fae9a7fcc0098b19b7ec3f660a4a084a395be064225ef0a6da7311b2bfda1f19b7c650a777c3a859cbd9454c8474b6d8c3fc80baa987faabc1acf9c37cdba4bb584ad0748ee09d5233d8aa17b4ca9340766f4da6a3d1dd4b55d17b049345622bd87198006bcb4ef48dccb9ed8cd642577af946ca592ac2d7f2a0948b826ac4d2f0a1678b3251cd71673cf45ea6c3596569df3dae9fd
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126599);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/10");

  script_cve_id("CVE-2019-1594");
  script_bugtraq_id(107325);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi93959");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj22443");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj22446");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj22447");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj22449");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nx-os-lan-auth");

  script_name(english:"Cisco NX-OS Software 802.1X Extensible Authentication Protocol over LAN Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, a distributed denial of service (DDoS) vulnerability exists in the 802.1X
implementation for Cisco NX-OS Software due to incomplete input validation of EAPOL frames. An unauthenticated,
remote attacker can exploit this by sending a crafted EAPOL frame to an interface on the targeted device to cause
system-level restart of the device and denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nx-os-lan-auth
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ec00caf");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi93959");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj22443");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj22446");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj22447");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj22449");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi93959, CSCvj22443, CSCvj22446, CSCvj22447,
CSCvj22449");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1594");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os_for_nexus_9000_series_fabric_switches_aci_mode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^10[0-9][0-9]V')
    cbi = 'CSCvj22447';
 if (product_info.model =~ '^(3[05]|90)[0-9][0-9]')
    cbi = 'CSCvj22443, CSCvj22446';
  if (product_info.model =~ '^([26]0|5[56])[0-9][0-9]')
    cbi = 'CSCvj22449';
  else if (product_info.model =~ '^7[07][0-9][0-9]')
    cbi = 'CSCvi93959';
}
if (empty_or_null(cbi)) audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '4.0(1a)N1(1)',
  '4.0(1a)N1(1a)',
  '4.0(1a)N2(1)',
  '4.0(1a)N2(1a)',
  '4.2(1)N1(1)',
  '4.2(1)N2(1)',
  '4.2(1)N2(1a)',
  '4.2(1)SV1(4)',
  '4.2(1)SV1(4a)',
  '4.2(1)SV1(4b)',
  '4.2(1)SV1(5.1)',
  '4.2(1)SV1(5.1a)',
  '4.2(1)SV1(5.2)',
  '4.2(1)SV1(5.2b)',
  '4.2(1)SV2(1.1)',
  '4.2(1)SV2(1.1a)',
  '4.2(1)SV2(2.1)',
  '4.2(1)SV2(2.1a)',
  '4.2(1)SV2(2.2)',
  '4.2(1)SV2(2.3)',
  '5.0(2)N1(1)',
  '5.0(2)N2(1)',
  '5.0(2)N2(1a)',
  '5.0(3)N1(1)',
  '5.0(3)N1(1a)',
  '5.0(3)N1(1b)',
  '5.0(3)N1(1c)',
  '5.0(3)N2(1)',
  '5.0(3)N2(2)',
  '5.0(3)N2(2a)',
  '5.0(3)N2(2b)',
  '5.1(3)N1(1)',
  '5.1(3)N1(1a)',
  '5.1(3)N2(1)',
  '5.1(3)N2(1a)',
  '5.1(3)N2(1b)',
  '5.1(3)N2(1c)',
  '5.2(1)',
  '5.2(1)N1(1)',
  '5.2(1)N1(1a)',
  '5.2(1)N1(1b)',
  '5.2(1)N1(2)',
  '5.2(1)N1(2a)',
  '5.2(1)N1(3)',
  '5.2(1)N1(4)',
  '5.2(1)N1(5)',
  '5.2(1)N1(6)',
  '5.2(1)N1(7)',
  '5.2(1)N1(8)',
  '5.2(1)N1(8a)',
  '5.2(1)N1(8b)',
  '5.2(1)N1(9)',
  '5.2(1)N1(9a)',
  '5.2(1)N1(9b)',
  '5.2(1)SV3(1.1)',
  '5.2(1)SV3(1.2)',
  '5.2(1)SV3(1.3)',
  '5.2(1)SV3(1.3a)',
  '5.2(1)SV3(1.3b)',
  '5.2(1)SV3(1.3c)',
  '5.2(1)SV3(1.4)',
  '5.2(3)',
  '5.2(3a)',
  '5.2(4)',
  '5.2(5)',
  '5.2(7)',
  '5.2(9)',
  '5.2(9)N1(1)',
  '5.2(9a)',
  '6.0(2)N1(1)',
  '6.0(2)N1(1a)',
  '6.0(2)N1(2)',
  '6.0(2)N1(2a)',
  '6.0(2)N2(1)',
  '6.0(2)N2(1b)',
  '6.0(2)N2(2)',
  '6.0(2)N2(3)',
  '6.0(2)N2(4)',
  '6.0(2)N2(5)',
  '6.0(2)N2(5a)',
  '6.0(2)N2(6)',
  '6.0(2)N2(7)',
  '6.1(1)',
  '6.1(2)',
  '6.1(3)',
  '6.1(3)S5',
  '6.1(3)S6',
  '6.1(4)',
  '6.1(4a)',
  '6.1(5)',
  '6.1(5a)',
  '6.2(10)',
  '6.2(12)',
  '6.2(14)',
  '6.2(14a)',
  '6.2(14b)',
  '6.2(16)',
  '6.2(18)',
  '6.2(2)',
  '6.2(20)',
  '6.2(2a)',
  '6.2(6)',
  '6.2(6a)',
  '6.2(6b)',
  '6.2(8)',
  '6.2(8a)',
  '6.2(8b)',
  '7.0(0)N1(1)',
  '7.0(1)N1(1)',
  '7.0(2)N1(1)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)N1(1)',
  '7.0(4)N1(1)',
  '7.0(5)N1(1)',
  '7.0(5)N1(1a)',
  '7.0(6)N1(1)',
  '7.0(7)N1(1)',
  '7.0(8)N1(1)',
  '7.1(0)N1(1)',
  '7.1(0)N1(1a)',
  '7.1(0)N1(1b)',
  '7.1(1)N1(1)',
  '7.1(2)N1(1)',
  '7.1(3)N1(1)',
  '7.1(3)N1(2.1)',
  '7.1(3)N1(2)',
  '7.1(3)N1(3.12)',
  '7.1(4)N1(1)',
  '7.1(5)N1(1)',
  '7.2(0)D1(0.437)',
  '7.2(0)D1(1)',
  '7.2(0)N1(1)',
  '7.2(0)ZZ(99.1)',
  '7.2(1)D1(1)',
  '7.2(1)N1(1)',
  '7.2(2)D1(1)',
  '7.2(2)D1(2)',
  '7.3(0.2)',
  '7.3(0)D1(1)',
  '7.3(0)DX(1)',
  '7.3(0)N1(1)',
  '7.3(1)D1(1)',
  '7.3(1)D1(1B)',
  '7.3(1)N1(0.1)',
  '7.3(1)N1(1)',
  '7.3(2)D1(1)',
  '7.3(2)D1(1A)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(2)N1(0.296)',
  '7.3(2)N1(1)',
  '7.3(3)N1(1)',
  '7.3(4)N1(1)',
  '8.0(1)',
  '8.0(1)S2',
  '8.1(1)',
  '8.1(2)',
  '8.1(2a)',
  '8.2(1)',
  '8.2(2)'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['nxos_dot1x'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
