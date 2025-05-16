#TRUSTED 23939c66cedeb6419c8e1cd729c2335ca488a23a3e8bfa1441730ade9ab14b813a0946da660b3c289a615fdf5234f0f8286f85a6af4e768116e24ede6e5fb6469d09430af305dbee9906bbda7e7bbd056bfe0f8c0ac9fcf984db4df29934b5edbbd6c56f65ae5cd8cd3762dc4ee949bd8df5810cccdd6a28ee56175323d7546c1eebbe469fdfc53ced46a3d2a49febd2c9746c840c354ef9f20b5c1595b537eb24256742e5eb80e24e9bb47c0f9c3f5e12c25b7659ccc54a6c60ae758a897be210950ad6a7038990190ada97bed99117aca566f4c451ebdaf1c1caeaf75bcc99dec7f72d09be4604630bc2cca1cee48b7b77cbb6d3b27b6d7120d22d871202f55434aa3baa3281d2342a39e4a4cc31c408bf42a48c515e98b592aed8ebf175ca5a3e8acc5dadfe78befc991a7fba43cb55ca61b42fbdd81449fa11072abf1fe0790f0755ccf6a8c4c32d2cf3019f56e03d2d2a4b0ccbbbb5108b6f97496c5521d6fb2375a6ddf128387080c2e5ef49946b36e387e907053311090cfe5d9f607a98c1a836512e53fdb716d59ebb57595c790b611c31c012efb6814d9a025aa1b34941160ed1c1ad2c96d5e45d3a952e1c6d874d953ef22eb50dacb8fa807792d927d237e082d3db63e2272f8c2bfaba616bb8be5fdd16fe70057aa48d621b421fbefc5654a696f097e982136dae564002ddd7674bd7a80c669344d402241fc862
#TRUST-RSA-SHA256 50ab7404e9484c30bd091524ed12fbc1b1d0b6b14d412fb064a2165e01e70ffad4aff9c91d7afcc7594823f55757a459689caff995b08df26ad01179c672bbf9ad113651e47b3107417ad58c551a31ad33c7cb544e17529042e7ad1a9d39a7e49266e1a3811771c86b39af933156063d687cff8d74e9fdad65a8554437f2cc89598422bddfa96fae12269ec38bbf4b2333cfd5adc1836016008eabadab97bb703cc84d9a0478136a63ab0ca53223d07b736a62a774dc96c0f1bc50f8b033d54b3ba43ee518580f12349c0be666001bec5de1d6f8223d61faeb8665039850f2aa871096192d0f2a7aed75ed74f8b315a244fcfc63844a7335bd52c734ff90c2b283e53d015c0ff3bb96668ed8e6e30dc942eb0eb2f00a088540208ef7b1ba878308428ab1e86c3a3e849e5f6f2dcb434fec4127328fcd77541d5c5b80fb63cf893ca3bcd119ad75c4ef045bb86e13c2c930d92ffda0c7d3815d9a17c1b25bfb9f7951dc94e42018e77ddab33634f92ba85c9aa80975c87dfadee1e2055b4afad858647665b8908e454fcd7ac659093ce9274563dec2de3cbc4c2dc39ad41ace2cd23e30728e496918d1f6ffb528a75d167c82353f51e71a84da86ea8a192052e8deefd84ff275d6cc5928bc50ddd0195d160d72f0bba32057dce3018b1e955f3c949164b105a7f47060d3d196744f37d7d214106bfe7762f16a114833e0a7eddf
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186227);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/04");

  script_cve_id("CVE-2023-20191");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe63504");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dnx-acl-PyzDkeYF");

  script_name(english:"Cisco IOS XR Software Access Control List Bypass (cisco-sa-dnx-acl-PyzDkeYF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the access control list (ACL) processing on MPLS interfaces in the ingress direction of
    Cisco IOS XR Software could allow an unauthenticated, remote attacker to bypass a configured ACL. This
    vulnerability is due to incomplete support for this feature. An attacker could exploit this vulnerability
    by attempting to send traffic through an affected device. A successful exploit could allow the attacker to
    bypass an ACL on the affected device. There are workarounds that address this vulnerability. This advisory
    is part of the September 2023 release of the Cisco IOS XR Software Security Advisory Bundled Publication.
    For a complete list of the advisories and links to them, see Cisco Event Response: September 2023
    Semiannual Cisco IOS XR Software Security Advisory Bundled Publication . (CVE-2023-20191)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dnx-acl-PyzDkeYF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccb9c2c6");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75241
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a0abd7f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe63504");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe63504");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20191");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');
var ingress_found = FALSE;
var smus;

var override = 0;
# Not using cisco_workarounds.inc because it's not likely to be reused 

# Check for mpls enabled
var buf = cisco_command_kb_item('Host/Cisco/Config/show_mpls_interfaces', 'show mpls interfaces');

if (check_cisco_result(buf))
{
  var pattern = "^([a-zA-Z0-9\/]+)\s+((Yes|No)\s+([a-zA-Z0-9\(\)]*)\s+)+Yes$";
  buf = split(buf, sep:'\n', keep:FALSE);

  var line;
  foreach line (buf)
  {
    var conf_match = pregmatch(pattern:pattern, multiline:TRUE, string:line);

    if (!isnull(conf_match) && !isnull(conf_match[1]))
    {
        # RP/0/RP0/CPU0:NCS5501-1##show mpls interfaces
        # Thu Mar 16 02:47:56.142 UTC
        # Interface                  LDP      Tunnel   Static   Enabled
        # -------------------------- -------- -------- -------- --------
        # TenGigE0/0/0/0             No       No       No       Yes
      # save found interface ex. TenGigE0/0/0/0
      var interface = conf_match[1];

      # check interfaces have either an IPv4 or IPv6 ingress ACL applied
      var buf2 = cisco_command_kb_item('Host/Cisco/Config/show_run_interface', 'show run interface' + interface);

      if (check_cisco_result(buf2))
      {
        var pattern2 = "ipv[46].*ingress";

        var conf_match2 = pregmatch(pattern:pattern2, multiline:TRUE, string:buf2);

        if (!isnull(conf_match2))
        {
          ingress_found = TRUE;
          break;
        }
      }
      else if (cisco_needs_enable(buf))
        override = 1;
    }
  }
}
else if (cisco_needs_enable(buf))
  override = 1;

if (!ingress_found)
    audit(AUDIT_HOST_NOT, "affected because IP ingress ACL filtering on MPLS interfaces is not configured on the host");

var model = toupper(product_info.model);

# Vulnerable model list
if ('IOSXRWBD' >!< model && ('NCS' >!< model && model !~ "5[46][0-9]{1}|5[57][0-9]{2}"))
    audit(AUDIT_HOST_NOT, 'xaffected');

if ('NCS5500' >< model)
{
    smus['7.0.1'] = 'CSCwe63504';
    smus['7.7.2'] = 'CSCwe63504';
}

if ('IOSXRWBD' >< model)
{
    smus['7.2.1'] = 'CSCwe63504';
    smus['7.4.15'] = 'CSCwe63504';
    smus['7.7.2'] = 'CSCwe63504';
}

if ('NCS540L' >< model)
{
    smus['7.7.2'] = 'CSCwe63504';
}

var vuln_ranges = [
  {'min_ver' : '6.4',  'fix_ver' : '7.7.21'},
  {'min_ver' : '7.8',  'fix_ver' : '7.9.2'},
  {'min_ver' : '7.10', 'fix_ver' : '7.10.1'}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe63504',
  'cmds'    , make_list('show mpls interfaces', 'show run interface') 
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
