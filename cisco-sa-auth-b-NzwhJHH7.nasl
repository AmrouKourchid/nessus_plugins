#TRUSTED 798146ca1a60e5441815ccdd963d0b8bb8c5ef34c8c5d077e926188c26ee6e05dd287745710c3ecc8983148fc0ad7c3a95e77b7edcab105a2d72665a0a5f2713a8a8556035d542c0de1b6ea1e6e1cf85fac5ba33028fba61d11436dbdd75b35ce6000be90acaebdfd36b9bd5de9c37abcc2c3470533d8e802f63fc9c4916b53761f3c0cf92a712ce5c9631e403847fe0cb6fb0e41ab7a4e8af80221a577f84c1a344382be0b747725aacc731afadf678b6649a7d1dce85c0cb73f9065303b92d2d3137d04d582131f09a175b05078033d4bafa1a6a02bfa8a786162a818b5ac8e708f5cf5d39c0f349c4b0c09a48f94f613d6a3ae548499ce821131b777124544f2992b2c9007b2ef24004441a8d6ecafd691e74de93ff88c0c82b7a1ae4f4a8a17353728718f85c6dab29fe1b04046fa74f762ae7d0062d1e391c6c3ea8a916fa303ad6cf0bd634ef1f5eac5e96f558da40838373b679bedf77cf66f4651e23d35ad892f56475c03d5c589b1adb39c49be4a09aef010b1ab5b5ec090168d3917a6cbaa9e25d544bce87b14a9e67a129f0e29a67a850cb025706d3fca73389918c0b831c9c92c91414fbe156da6f0e1f307d83b9be397fb5381d07444335770364bada26ba5a9b3d744b22dc2aed7880735a2e328902370bb1056e3e5314f8621f5ed63b482669ab928669a5637f11221318efd424e5b597f7bbba71031fb7c2
#TRUST-RSA-SHA256 9a51d8006c40e72561f80f1ac2f299d9acbff1f379792d2303ad89fc0ad73787645688d30be89d2fdea0ddcbf587608ef711535a7d6082a12ae80305933525c9201db6892bd76a9e84ebf4af2b8f843d666f799dedfa802f19fa8fbc41ae9c7b08adee1890ef95e33364d31bfc748c343976a4deff832b11f12f1c2e0759519791ef656a9d9adf00620e19fac8c68e42a597cdb62a215a7c9e0e72046765e1468c1c88381c1237f7a3283d46375433e5222634db1dd7b759cdfff0b6866b41eacaf8d0a423e13f5c0509093701d5a891eb5e8d3d4be55a86937c17952e372f0864b9b41e301c61d5c6e942c23ce3818a03b4bed3902693f3b47256894be6a38eb55e99b08eb46402938ca8196a6fa9c7bab06bcf29e12eabef6a399cb2efefe998a1d60998dfb22bb415264f1e5a7287011bbe3e21272b306239bbaba1014f2ff0880bb16ae5999a4e48e7954df13c639a14ce0c8aa23020aa233982c7fa96c481976310ef139574f5dd9f293739cad75fd5248b86f0939a73afb0bd899fb03a631d44306232d2f744459267fd680d76a6f46eda6bf2fc898f1dbc5d2a6d9cdd75131deb2521c3610d0fc1c3a23279aa65a640818bb68bd1bcf70e1aa2f710a1e0b6d0897dd60537c51b94c4baac96bdc79175a40b678eed68e6c4c7697064202de2e60a552314fa9011bfcc19102703dfc01278f83fde4a8ebe21556254f118
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139517);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3216");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk38480");
  script_xref(name:"CISCO-SA", value:"cisco-sa-auth-b-NzwhJHH7");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE SD-WAN Software Authentication Bypass (cisco-sa-auth-b-NzwhJHH7)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE SD-WAN Software is affected by a authentication bypass
vulnerability. The vulnerability exists because the affected software has insufficient authentication mechanisms for
certain commands. An unauthenticated, physical attacker can exploit this vulnerability by stopping the boot
initialization of an affected device. A successful exploit could allow the attacker to bypass authentication and gain
unrestricted access to the root shell of the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-auth-b-NzwhJHH7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52d778ec");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk38480");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk38480");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3216");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

vuln_ranges = [{ 'min_ver' : '16.9.0', 'fix_ver' : '16.10.2' }];

var model_check = tolower(product_info['model']);

#Model checking for IOS XE SDWAN model only
if(model_check  !~ "^[aci]sr[14][0-9]{3}v?")
  audit(AUDIT_HOST_NOT, 'affected');

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk38480',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
