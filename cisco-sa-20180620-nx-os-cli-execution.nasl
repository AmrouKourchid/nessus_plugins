#TRUSTED a293669db8a116390b01f14f8521fb87d625d9ae4cf77a98fce229fa76d9d2b33262647c0524cdc8abb62558384c178ddfd84ceabff9c0d289ad0aa44754b0cd9278e70faa0e9d4e8cf59624822768fb317d95a8ad37af6ec5ba58ee1e444c5e9cc7d102c0a20ec92da01ec424e3ea718097e1634ffe932382dd444979e83d1d5b20d9c2cfe9451d6b2fc1c17600e5bbb287aea91d1358fbe5fb26dc3a72b635963171b7a1462b2d521a0ab34d8992017a6f9a6963f089780dbe20da9e96ebde1869abe0e183a9298ffe7ee7bd7a2806e7b18755695005d37ba610b8272dc03d8f396c992c7d0b5b16d591d83a82afbbce6d2b6f060511ceca9bd72d79379d3f7883082dd0e50ff53167b4aab32a70cb1471ec8ae3d47d0104158ce8e05c5cf9e8b61af6714a3f1c293b6d8e17346f1524aefc2685862b3e11ef86aa9659886e7985e3b731ba19262442b8def1725edda080b67c5787ba84341b306fc0d6ea2f51b4986ac822f2550030089ffe0d8cb1ff36e5360530b8f6c2acc9ee2133e7b6367021681cbd008af6b3e97fa410c3e86316865128862979c4640a19087dceaa55d143c43a14c8608effeacc92866ce98e697ac433895ea1c130efd63e3dc66622d5ff2c33b717634469f30f7b8cc1d959430b2f2fa5a67c3ba72a447f309910570d1bcf9d2fe971046436d8f22fb3f3d7c203cf3fd4350671519e642c66b2d3
#TRUST-RSA-SHA256 a91176fc6f60685d8ab63e068d22d87b0cb8df32846057d635c532ad917320c584fdba0181f0c609654b5ab02517258b5b15f46b8def569687d87eefefecde06cdfbf782e897f00d994a2349b4eab74d9cebd560de7a6de0841b201f53c93b820f6dc41bb021da40e7d104edfa74579fc5023980a64ed0ac462fbbf438105f9e81c3468134cc197a816be647a0eb4df25ff8c8879aa69ee6eaa0cc1e266351483c275db08e74d4dfbac8ac739d0bfbef998621dd31090a691ce2eda62a02e46199d2d7dbd6037a0fc4aef07793464bed329892214edbfad8e5de1970eda7ee7d6b54a9a50c672519658110a459006aad855032cb8c87e0cb9555cda60ef87ee24966e4569e4e9c54a2cddfe4bc002859a1e2decd01c51fa19b8e3baf6c61ebb32f64dbc087743c3acce4203554b03fb9483433879511eff6a72732da090ce2823c47f807b42447e2a4f6d59b01fc41abb7d03e03bd8456b6ef9458d195cb36c2552bee34c80c915adf9dec3970b625b7281663ad83da145776e3e8961b29174a040bd2a6e9a8b01e56a2d98e857269e26ffca99d3872139a004383c27087aa993a67f48ea6adfe50e93a53d2be8cdd34ab05eae8a48d764aa4447b6af4fabf3fc57d5abc3c6024dd53384a5d7ea01bcfff3f904161c60fb089baa026653d942d925882f407e6e23bc33cb8226ee7f50ca20219181ce71da67d22c60c00c67f6b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138348);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id("CVE-2018-0306");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve51693");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91634");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91659");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91663");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nx-os-cli-execution");
  script_xref(name:"IAVA", value:"2020-A-0397-S");

  script_name(english:"Cisco NX-OS Software CLI Arbitrary Command Execution (cisco-sa-20180620-nx-os-cli-execution)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a command injection vulnerability
 exists in CLI parser due to insufficient input validation of command arguments. An authenticated, local attacker
 can exploit this, via injecting malicious command arguments, to execute arbitrary commands with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nx-os-cli-execution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea7fd148");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve51693");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve91634");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve91659");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve91663");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCve51693, CSCve91634, CSCve91659, CSCve91663");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0306");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
var version_list = make_list('');
var cbi = '';

if ('MDS' >< product_info.device && product_info.model =~ "^90[0-9][0-9]")
  {
    cbi = 'CSCve51693';
    version_list = [
    {'min_ver' : '5.2', 'fix_ver' : '6.2(25)'},
    {'min_ver' : '7.3', 'fix_ver' : '8.1(1a)'}
    ];
  }
else if ('Nexus' >< product_info.device) 
  {
    if (product_info.model =~ "^1(0[0-9][0-9][vV]|1[0-9][0-9])")
    {
      cbi = 'CSCve91663';
      version_list = [
        {'min_ver' : '5.2', 'fix_ver' :'5.2(1)SV3(3.15)'}
      ];
    }
  else if (product_info.model =~ "^(20|55|56|60)[0-9][0-9]")
    {
      cbi = 'CSCve91659';
      version_list = [    
        {'min_ver' : '6.0', 'fix_ver' : '7.1(5)N1(1b)'},
        {'min_ver' : '7.2', 'fix_ver' : '7.3(3)N1(1)'}
      ];
    }
  else if (product_info.model =~ "^90[0-9][0-9]")
    {
      cbi = 'CSCve51693';
      version_list = [
        {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(8)'},
        {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(2)'}
      ];
    }
  else if (product_info.model =~ "^35[0-9][0-9]")
    {
      cbi = 'CSCve91634';
      version_list = [
        {'min_ver' : '6.0', 'fix_ver' : '6.0(2)A8(7)'}
      ];
    }
  else if (product_info.model =~ "^7[70][0-9][0-9]")
    {
      cbi = 'CSCve51693';
      version_list = [
        {'min_ver' : '6.2', 'fix_ver' : '6.2(20a)'},
        {'min_ver' : '7.2', 'fix_ver' : '7.3(2)D1(3)'},
        {'min_ver' : '8.0', 'fix_ver' : '8.1(2)'}
      ];
    }
  else if (product_info.model =~ "^95[0-9][0-9]")
    {
      cbi = 'CSCve51693';
      version_list = [
        {'min_ver' : '7.0', 'fix_ver' : '7.0(3)F3(3)'}
      ];
    }
  else if (product_info.model =~ "^30[0-9][0-9]")
    {
      cbi = 'CSCve51693';
      version_list = [
        {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(8)'},
        {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(2)'}
      ];
    }
  else audit(AUDIT_HOST_NOT, 'affected');
  }
else audit(AUDIT_HOST_NOT, 'affected');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['license_usage_yes'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
