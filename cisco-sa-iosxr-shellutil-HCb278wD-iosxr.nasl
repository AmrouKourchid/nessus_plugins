#TRUSTED 0625a912fa8e7226d6ee6cc7e52c1fb5998d6d7e4fc77d192c931f4010525c37c032bf9326e9c56ce11d493c6c70b808df9f740bf3b852321cef6ddf10650edea2f4307f0cea1dc6f77455b70dbda6f737cd9fa12d69e4475ab7edfd2517ef54aa09ae4e38feb7bbfe2bc755fba16218e44ffbed9bef31917da3938b9d52897a491ca4d4b3d9dcd3bd7f9d556d2262beec26e2f8a4021a7883c21d852f891b7bb3a046b949beaa77341f3b0b5e5792981ec6f97aa43ace1f00be214c62208782767ba4f2bcbb551d8ba5aec14d98597f287b518e3d5a1b46f4b92667639324c3a3042b39d2c03a10e2c5fbf62936653bc1612eb19a01acb6fed04db6aa01b185d61df7210ade33face7db9869cf3dc02905812450745240c3ba1cfbfa24755e9f82fef828f4c98bd89649acb5030ea7632c4bdf5c9b7d377382c97db3383690e5f10d4e6459cdf563751f355d09cf482a1afb00638e881546ded79498593b04923bf60d903d7b57f7bbd96af3da33dec9e3f304a67d36c40d952290c5444e7ba815b605aea0063a6e2a4d8da490839beccb9dfe49f9deaac45f65d9feb37dc21957d1175f20aa7b951f20314797b3e6363595f25059bae6edff699f78443e1b37dcc794653425dfcf2e7809ef7077d03cbf79e700d485c54644db47f8ca45e902e57fa96d66ffd1d4973adc0f47db39218ab745e07aaa7ea4437644e641b3eea
#TRUST-RSA-SHA256 5d9ab36221b9cf85a97ffac012a0233dd0a2d67330e0cbfbcaaab69065ed0fa6ba0b2d2c30ecb4aadc7b037bc0b887537b3142331c7acef3e0debc7603d483f19fea7ae0e07aa60121b16fb0c14082fccb3b165c35841fa39bd63c9606e9d4ffd5122036ecdeb8fe32ef4d7adda6479e4b90ff0722781884730ab8273709b12da9239f4e48abd35666120ed4d94158b8c0f35ca26ee6bd624594b9fba3be60647bbc83d99bc175d2ef9e96637c9ceb788b18ca8ff1030a21d09cd99ff8914d72a11b74366ca657cf56173da2abde33de8375ddc776baa957b264865260ae0fb0dc1c71221ee88871dc9d041012766f4d00722b208d671f27c95da69f5df0dfbe582af1b093afa0d400551e8f8c644cad19e157a84b1e5298306092d873153c080767657839430e55e2d698cb2d3ff1bb4c698dfab9b6b57d4a5b7c0a79a42d95efb9e25fc1c6cc60d26cef237d9dcc7a65016d391b78a9a82d6e72c1cda14b1ce6eb52fde4fd148b521dc85efae60c47f8c67e4872f09c557290ac4152ca7070f139073bc3b1acbc28a01243d389b7244772f901d80fcb644d715129f91155b46b2a3b3226b0143ce8c4e5db4034de50d75c91fa73db5c8d5403b3892356fea7a1252c862d31128c308e008e136e1e3bd99f8d79aa5c2fc86db3592896ab77bf3b8c4e90f0dad87d33197cb92b0b6dd43690c913bd28c1b1bc9946e9df42de34
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207523);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id("CVE-2024-20343");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi71881");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-shellutil-HCb278wD");
  script_xref(name:"IAVA", value:"2024-A-0573-S");

  script_name(english:"Cisco IOS XR Software CLI Arbitrary File Read (cisco-sa-iosxr-shellutil-HCb278wD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco IOS XR Software could allow an authenticated, local attacker to read
    any file in the file system of the underlying Linux operating system. The attacker must have valid
    credentials on the affected device. This vulnerability is due to incorrect validation of the arguments
    that are passed to a specific CLI command. An attacker could exploit this vulnerability by logging in to
    an affected device with low-privileged credentials and using the affected command. A successful exploit
    could allow the attacker access files in read-only mode on the Linux file system. (CVE-2024-20343)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-shellutil-HCb278wD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8fe063a");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75416
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a636b5a5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi71881");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwi71881");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20343");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var smus;
var model = toupper(product_info.model);

if ('ASR9K-X64' >< model)
{
  smus['7.3.2'] = 'CSCwk94350';
  smus['7.5.2'] = 'CSCwk94350';
  smus['7.7.2'] = 'CSCwk94350';
  smus['7.8.2'] = 'CSCwk94350';
  smus['7.9.2'] = 'CSCwk94350';
  smus['7.9.21'] = 'CSCwk94350';
  smus['7.10.2'] = 'CSCwk94350';
}

if ('NCS540L' >< model) 
{
  smus['7.5.2'] = 'CSCwk94350';
}

if ('NCS540' >< model) 
{
  smus['7.3.2'] = 'CSCwk94350';
  smus['7.5.2'] = 'CSCwk94350';
  smus['7.8.2'] = 'CSCwk94350';
}

if ('NCS5500' >< model) 
{
  smus['7.3.2'] = 'CSCwk94350';
  smus['7.5.2'] = 'CSCwk94350';
  smus['7.8.2'] = 'CSCwk94350';
  smus['7.9.2'] = 'CSCwk94350';
}

if ('NCS560' >< model) 
{
  smus['7.3.2'] = 'CSCwk94350';
  smus['7.5.2'] = 'CSCwk94350';
  smus['7.10.2'] = 'CSCwk94350';
}

if (model =~ "8[0-9]{3}")
{
  smus['7.5.2'] = 'CSCwk94350';
  smus['7.7.2'] = 'CSCwk94350';
  smus['7.9.2'] = 'CSCwk94350';
  smus['7.10.2'] = 'CSCwk94350';
}

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '7.11.2' },
  { 'min_ver' : '24.1', 'fix_ver' : '24.1.2'}
];

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwi71881',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
