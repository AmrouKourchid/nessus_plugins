#TRUSTED 3f229c07874607da1adf49da88a2becadedfbf7d6e7725f77e3bf020b7ce183ccef4acdae33a788766e04953543a4bdca2a7d84e04c76b18a6b95c4d2ad4e62d1f3492ff46836b277cdfd7fe269f0ebad8671e9aa7e9e0c8e3070787627157f31df34d197b940ef39bf0442a3abdafced48a99f42d8705862c975f3d69b0201f884230c36aef85386f588ce68763a7a77f0e96d752ac7c07cf09aff3aea923b7513c51d50f8acb97737566daaa498cb2af834bbccb6731747ad6d9c1a5d692d1759d69eea5ce3fb9cc213d971ad2e83342dff40e02083f47007a663e2e41df0dd38d0b78cebe2726fe2ca4fc2e4bdac37d77b9e952bf2bcbad212ab904c46943e78a74d72dc057daef865124bdd32f47a558946307d61495f53872c2448e5963311def6e6f49a935b4d0a35770228af8684a58b99ae03b360d675e6f7594f0600bf1f33a19c58a16d03ee0b8ef7e68346d41bd92dc5ae99cdccc8f055527629f45318476d4766b3c9b797ed8641f6e539a75bf041f58c507d301f995a369a2b0637894db9b84a0059335132db4604f14237ec831fe6e5720a347e5763d02a2ea9333af2c7d236ff433e12461577dd614813e66fc0fcc01dda5cf922b504d8ed70a17412257cbc93d2f6dd32a6e72411ae1ecbfae67501b25ddd7a8cf5148a1442d6e6b26c6074212bb79fe2b7c23c9b985721dfcabede56641a9b7287625f0db
#TRUST-RSA-SHA256 4efb51597cc769c388e32c3c40d314c1d897a0af0eb3ab139d5b1bfbce5adfffa1cc3ff8cc21e2404ea7a291dddaea3d17d06d1b092b22a5afa7bee2261a3b05dfcd988c08f6ff324ce9c1111264f7c39cea87d79c7ca2357b8666187c78be8643e5777427d7cdc550f25521cc26435b63e2b92651dd54a36417eb0e9a0881b8176e865226b6c4cd8012da619db03a307cc262ad2b3bc541bc5d72a8001c09db2ad0d0395dad1b0c016104fb4c2b3f84ec26cb31d4970c094da8250ae91aa09475a97b00220f4a39ff9cf35c58534504cf105baa0a3ae5d7229a11850838426dae8159dc79983adc29fe4defaef203d822f49fdbae0ea391573234bf9063253e0dcf776abc65ad10ff3759155dd196aa0d31260fd453a795efc6fe541bffc5a77c4876e3fd7a7988159604c1fa74f6c3871ef3d7d7fb8cb57b4507329f5da5d47a3a5ac991fc5cb505521fa6cd0a513c0e361e22ddf5ebf5e2dfb14298f6678daae60df7b630f2baf5fc5f50b14faa68bb3553c9326768a3a568faf451a8a8833b9daf38424efe5c0253e4358c98cda3cc35db84312567f6093be7fe40e68051f4ab07b02d8d8976ce7b53067aba910539d0653e6f7185681ba8eee68f09f4098f5e02e097b5571a7aa449eb480ca4e523d7b0269dbe3557013c988539004e02af778c5a1b70632b2e985b3d358524d204f93b3f3d2705e27a90e9b55b7c0beb
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159517);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/14");

  script_cve_id("CVE-2009-1154", "CVE-2009-2055", "CVE-2009-2056");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtb18562");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20090818-bgp");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Cisco IOS XR Software Border Gateway Protocol DoS (cisco-sa-20090818-bgp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software with BGP enabled is affected by the following 
vulnerabilities:

  - Cisco IOS XR 3.8.1 and earlier allows remote attackers to cause a denial of service (process crash) via a 
    long BGP UPDATE message, as demonstrated by a message with many AS numbers in the AS Path Attribute.
    (CVE-2009-1154)

  - Cisco IOS XR 3.4.0 through 3.8.1 allows remote attackers to cause a denial of service (session reset) via 
    a BGP UPDATE message with an invalid attribute, as demonstrated in the wild on 17 August 2009. 
    (CVE-2009-2055)

  - Cisco IOS XR 3.8.1 and earlier allows remote authenticated users to cause a denial of service (process 
    crash) via vectors involving a BGP UPDATE message with many AS numbers prepended to the AS path.
    (CVE-2009-2056)

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20090818-bgp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2554a1bf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCtb18562");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCtb18562");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-2055");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2009-1154");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['router_bgp'];

var vuln_versions = make_list(
    '3.4.0',
    '3.4.1',
    '3.4.2',
    '3.4.3',
    '3.5.2',
    '3.5.3',
    '3.5.4',
    '3.6.0',
    '3.6.1',
    '3.6.2',
    '3.6.3',
    '3.7.0',
    '3.7.1',
    '3.7.2',
    '3.7.3',
    '3.8.0',
    '3.8.1'
  );

var cisco_bug_id = 'CSCtb18562';
var smus;

smus['3.4.1'] = cisco_bug_id;
smus['3.4.2'] = cisco_bug_id;
smus['3.4.3'] = cisco_bug_id;
smus['3.5.2'] = cisco_bug_id;
smus['3.5.3'] = cisco_bug_id;
smus['3.5.4'] = cisco_bug_id;
smus['3.6.0'] = cisco_bug_id;
smus['3.6.1'] = cisco_bug_id;
smus['3.6.2'] = cisco_bug_id;
smus['3.6.3'] = cisco_bug_id;
smus['3.7.0'] = cisco_bug_id;
smus['3.7.1'] = cisco_bug_id;
smus['3.7.2'] = cisco_bug_id;
smus['3.7.3'] = cisco_bug_id;
smus['3.8.0'] = cisco_bug_id;
smus['3.8.1'] = cisco_bug_id;
smus['3.8.2'] = cisco_bug_id;
smus['3.8.3'] = cisco_bug_id;
smus['3.8.4'] = cisco_bug_id;
smus['3.9.0'] = cisco_bug_id;
smus['3.9.1'] = cisco_bug_id;

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'cmds'     , make_list('show running-config'),
  'bug_id'   , 'CSCtb18562'
);

cisco::check_and_report(
  product_info      :product_info,
  workarounds       :workarounds,
  workaround_params :workaround_params,
  reporting         :reporting,
  vuln_versions     :vuln_versions,
  smus              :smus
);
