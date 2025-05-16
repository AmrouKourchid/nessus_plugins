#TRUSTED 49da1aa1c91c702906f2d26a41d1a06977859d3809dd2ed25db8b3ea533a8f600dec9c8564bc68a81264dc7a5efa18dd96eb291755ad46ff91498c5c260a0e6788da13f83b27ef2a371fa52193d3e82b1a60d5ed017f6e102d9fcc918ada4de65141e0fbba20cd32e74b8c54a3440903d1b5ad5298daf1a75066815cc972feb7ed73e249a8c5514247fe35add77b730cb2de547a16729b8db00fadd641d1f0d2606cfbd42a626c9fc30c869cb23858192f1580b1a118afc1782df17c764f24073e2cd7ef7f14958209823b5d69a85115db675c86c48dd665e5093e122165f437632be212d72cd30ea05f384cfb395c10c930de4bad3cd8eb154da0e91d456156a59ceaf0591316b23d9c1533b98593b2f9963cdb0f85c62daa27c333a4c4852c801c0787e7dc2a5e0e2e66f840f4248bbd8a9723aa911210707e530a95d617724b41fcd2cd8c4c4a8a6df448f0bc958423d7ad4104a8c847d1305ad9a8ca8203206edfeff38f49bbd0b436fc898d3d0f864ea5fbac7c1f3eb9c84a4a87ea515993e0e2c7181787217408410038d7dcf6cf4eb832f6d875f450f4f29bfe6198cac509830dd242996896135f4839a116ba76f6f8c07ba14885059848c22ed1b8e81ed153bc0be2a990e3b98826f1779abf8965baaafaef775041c76a02b909f5597a9d411cde16e2e0cd47b8cba55c1188ce9323c2a1c4af43b1bf609a61bb54f5
#TRUST-RSA-SHA256 0808464434eef7660ed10642154bb47b67744b3ed548829a114b9696b72a60032431a04b6cb7cce9b27aa7a1fde8c761680c0068079711414c7eb426661ba846a9ce3391858d8aeb9d3cc45dee13d9048a1f5ebf7b58c0881084cdbfe89c6276f96db4c9e1a791275a2484396dceea5824739432b969fe4d608e5fb7f6f4d570ea83bf9ee5d39d4c223df56e5d7841ede37aec7a35d1c7bd15a359fc3dfcdd621617c408dc520f30bc4c4f77374a11b949a788edbfdb0cadb05aa888b29af9a3437ae3eadc8f6e6a0ec0b2d3d12564ecbaa084c256470ff6df10d4af6adc39fd861ae544028dce8b6066db5c1eaba09c3033d92b9aeaf70b8180a96e00ccc404d6d6034b827d34d28a3a4bada68682448455c6c6dffad2a33093810c23e063570b6b6ca3f772c6f02f0979452683ae0affc625cead880f8f1a788feda027f6169f81421490b3166479020057bc8a7954299da7555069c28996bcc8199efff157cc14b5fb2099402ad3587940de73d67defa727ea52cb99d5b0dd158527d3d0f4f2b065076da0f6f46ba5f5a28c27f86f74ef22e4f0421d3de41e22d75f3ce7f4bb40d2751d5b0bc3851cb000f34c5ca7b66eac8b292f3b920dba29670143fb18f8f641e026875c51ce4533f0db6f3a0f9aabf88f244927226ed1f3a05c434e9d5a5ab06713094151416189eefc9456ac28913bf590af49124fa4dadb1e8c400c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127917);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1754");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi36813");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-iosxe-privesc");

  script_name(english:"Cisco IOS XE Software Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in the authorization subsystem of Cisco
    IOS XE Software could allow an authenticated but
    unprivileged (level 1), remote attacker to run
    privileged Cisco IOS commands by using the web UI.The
    vulnerability is due to improper validation of user
    privileges of web UI users. An attacker could exploit
    this vulnerability by submitting a malicious payload to
    a specific endpoint in the web UI. A successful exploit
    could allow the lower-privileged attacker to execute
    arbitrary commands with higher privileges on the
    affected device. (CVE-2019-1754)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-iosxe-privesc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56dcafb4");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi36813");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvi36813");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1754");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
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
  "3.2.0JA",
  "16.9.1s",
  "16.9.1d",
  "16.9.1c",
  "16.9.1b",
  "16.8.2",
  "16.8.1s",
  "16.8.1e",
  "16.8.1d",
  "16.8.1c",
  "16.8.1b",
  "16.8.1a",
  "16.8.1",
  "16.7.1b",
  "16.7.1a",
  "16.7.1"
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvi36813'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
