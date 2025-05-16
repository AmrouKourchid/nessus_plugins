#TRUSTED 62ea018c2949cafd350fb792c384e0a75d77322f468b4622a4585bc61f185311e166d0fe8887df5315a870c2f977c3b54d33d18509c028055583417caa114cd4c0adfe6bfb2d02cb84e8c662c24351d6611ee10b2abeea171e947496795998f6213b13eb1af8a9ff7cc56bfce89f72d1f7a7da910ac67d194d6eb7192a796e1dd4bae3ece4a4af602b9211b25ee0d755505f9eeaf387edfd89d915eff20facc99f95fd779a1396dc939a50c1ad6753e19473d2b748be595fb52cc6ae65a0634d7e751767c44c366d3fe9296839be42c60577a52f86a2e00b1ed4fa6b845aee174b3179c6b04f6c02f17fce1653a636b507b017886105100aa0b1a0eb5f0eaee83ca14a035647122260bda486d3796158858a65b33904369dfdfcaaece40e6ed1e58b3a56b9692655f236ddbb18b280b1cc307b23ebbb1f587367f4c420a4b43b67c39572add77512d8687400a304c22af1bffb81d89a6bc713584504cf9909facab742f4c220ec7c1ad437183c6d86640aa028349e5936116fc4e5a26c178c67bf27e78c58e49780afe542a60e3e839bfab84d4f9c279d3e09b7aa4784badb2ce3cb05735d522b469c209f69f3239fb3562e7dda4055ff82bed93ad2a03080383f2707274e26b184f6863e897cbb02bd9984c6cba1f436baacb7335ac5f744e722cadb34d507748014326d943f8d6c07fa69b707c012362bee0de92b31ce05ff
#TRUST-RSA-SHA256 64e1096726ae4626c861b35b36e77f55593b91c307f75a97dbbfb9f5a377a860b652e9883820599ce4d49aff74cd270f76a71afb284eec5dd020826dcb9612e6c6339011b79e02549432e2bc37a67e27321850ee729473ccbd366425b1f0619ef5690af411cd2790252ce9bf4cc9f899345eb2c111c924e7ee0ecce4f4f133bca7bef6c634f4676a4a9f0c7b87a3aeb601e8ccc272fe190688f6097ca5c56bb384771d5fb45a81998a4e73cce32af7f36274436541b24f09e91e9b90348c72a435bdf55d959ae70355593dd647db6a63cb588e4582131011a502efdd2b501b3ef668f3906ad82dccfc9670f5163fcc1e8f22f46fa6bf7d297827d8b088d9f04b8c4d9c82fddee8ca6ac04b4cf93d479026231fd04a5c5a8a54a109c53c4339f26bc94c72bd95a75a1e0db27448db4c798bf9ae4610c017bbbda5b9bf3d48b3ed3494394d753084cbcad7963805430f7602c80e5536f44ea274d09141f1d550958b5a3331394f99ff1c1d54b50d6dd02ca8076f3d601f7da14d1201a179848d5f109bb3c8ee58b6a84ff284c66694e45151920acaa6d4966612e5727b2516e1db056ddd15a6e8cf75f7475074acc51b01c600eac071637ce1f9e8c1e32f0a97a948a6cc4dc0ba4f3fd906309806023da9e504e1f2e91555a9d23b14ddf39f850dccd7cd94d6d342c58b2dbe38748bafe32f166e2c98afdb02d08df2ecfc23c38d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123790);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1757");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg83741");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-call-home-cert");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS and IOS XE Software Smart Call Home Certificate Validation Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in the Cisco Smart Call Home feature of
    Cisco IOS and IOS XE Software could allow an
    unauthenticated, remote attacker to gain unauthorized
    read access to sensitive data using an
    invalid certificate.The vulnerability is due to
    insufficient certificate validation by the affected
    software. An attacker could exploit this vulnerability
    by supplying a crafted certificate to an affected device.
    A successful exploit could allow the attacker to conduct
    man-in-the-middle attacks to decrypt confidential
    information on user connections to the affected software.
    (CVE-2019-1757)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-call-home-cert
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d1ccbd4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg83741");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvg83741");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1757");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(295);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list=make_list(
  "3.9.2bE",
  "3.9.2E",
  "3.9.1E",
  "3.9.0E",
  "3.8.6E",
  "3.8.5aE",
  "3.8.5E",
  "3.8.4E",
  "3.8.3E",
  "3.8.2E",
  "3.7.5E",
  "3.7.4E",
  "3.6.8E",
  "3.6.7bE",
  "3.6.7aE",
  "3.6.7E",
  "3.6.6E",
  "3.6.5bE",
  "3.6.5aE",
  "3.6.5E",
  "3.6.4E",
  "3.18.4SP",
  "3.18.4S",
  "3.18.3bSP",
  "3.18.3aSP",
  "3.18.3SP",
  "3.18.3S",
  "3.18.2aSP",
  "3.18.2SP",
  "3.18.2S",
  "3.18.1iSP",
  "3.18.1hSP",
  "3.18.1gSP",
  "3.18.1cSP",
  "3.18.1bSP",
  "3.18.1aSP",
  "3.18.1SP",
  "3.18.1S",
  "3.18.0aS",
  "3.18.0SP",
  "3.18.0S",
  "3.17.4S",
  "3.17.3S",
  "3.17.2S ",
  "3.17.1aS",
  "3.17.1S",
  "3.17.0S",
  "3.16.7bS",
  "3.16.7aS",
  "3.16.7S",
  "3.16.6bS",
  "3.16.6S",
  "3.16.5bS",
  "3.16.5aS",
  "3.16.5S",
  "3.16.4gS",
  "3.16.4eS",
  "3.16.4dS",
  "3.16.4cS",
  "3.16.4bS",
  "3.16.4aS",
  "3.16.4S",
  "3.16.3aS",
  "3.16.3S",
  "3.16.2bS",
  "3.16.2aS",
  "3.16.2S",
  "3.16.1aS",
  "3.16.1S",
  "3.10.1sE",
  "3.10.1aE",
  "3.10.1E",
  "3.10.0cE",
  "3.10.0E",
  "16.9.1s",
  "16.9.1c",
  "16.9.1b",
  "16.8.2",
  "16.8.1s",
  "16.8.1d",
  "16.8.1c",
  "16.8.1b",
  "16.8.1a",
  "16.8.1",
  "16.7.2",
  "16.7.1b",
  "16.7.1a",
  "16.7.1",
  "16.6.3",
  "16.6.2",
  "16.6.1",
  "16.5.3",
  "16.5.2",
  "16.5.1b",
  "16.5.1a",
  "16.5.1",
  "16.4.3",
  "16.4.2",
  "16.4.1",
  "16.3.6",
  "16.3.5b",
  "16.3.5",
  "16.3.4",
  "16.3.3",
  "16.3.2",
  "16.3.1a",
  "16.3.1",
  "16.2.2",
  "16.2.1"
);

workarounds = make_list(CISCO_WORKAROUNDS['section_call-home']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , make_list("CSCvg83741"),
  'cmds'     , make_list("show running-config | section call-home")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
