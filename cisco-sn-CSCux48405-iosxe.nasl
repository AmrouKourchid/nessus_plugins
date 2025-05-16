#TRUSTED 745a01841d919ed3f92aaf0efbc696c4cdbaacbccf638b346ca0aceaf5be6e5348351ce3415595a1174184fa7e89b7f303be916234ed6284e9dc3469d5cfec2ac2115d0d2d9e9d6c2813223edbfa0be73b2cc13e826dd05d586a28b2280bd3b180556daccf8703f28f7dcb9d8d729c0e3cf31f86dadde1c6700c0776154afabc130c75a7584b317caca4257219c8208d04ac17ef094c70c0923769d002ba8c987dca1cf4ba545b32eeb875be205775fd22f060e3936621f4814a8a4218778bce08fa553305981256f58c59f4ce957a5721f6586eafebf49f4039c1ea72e501004a83bb2575b91249e7b4b2943b69642ba73fc194814eee5e12fa03c59fcc14c67e348ab0764b1bf56d14f89b6ef75048a518559a1e72dadfa4261012e8c03ccb20d71c0007023fe152d8f8a5b59d425229ccbe83e7a606f7dc938c70080e72e68faf1f2a50a3c6403422299ade430f458c03f2837e50b7206f38a57be721170efd29b4cc2fe42e64944a4d7d899a98ec9dfa33e9865a4dbc7e66496439541275a8e6e352ca0b088338f29abd2da05ac72b80c2164bfb8d7e977561539338834f4128366f6c5c0e10e67aedd6073a18d460b95457c822c6f647901f7e03d487cfbd8b8324523c36116f30b681fa86215e70bc9d6a15559d7e85f53eb742d36662e92f4ba4705f72284da20505dc866005884cc3ee441fff0da16e52ee4c611bff
#TRUST-RSA-SHA256 23b37ec62e4b2efffa038d436b6c492a054350efc5a9ed0d125cea98f1cf58134b103abfda48f2a0379d8b5cc5e11adc840fd08e34bc510c63660a559625ffdbef082e0dcd6e72397d9d92eac362bf6d3a971e21e521db4000f5d27428f2f69d81881c2992655fc5a5b6cd0540f309ec82e9d49245c572adec7c9d80544a25c2a5507aa6395a539888387a95cb3b11d5e28b6e5fcd98dcdcd0a8e5289364af8ab3563fc02d961ba727f0bde9c29fdfedb68c289b0edafacc33fc1d3f662f5e1ccaa52a5f04b29a44293b9cb93c63adf90c7e9ddfaf2239ba2fb05c94df4e65c38f3d8cfe25f076b7e3c3434062d2f79d8add097da44f9a594d47a4773b9552ab485631ac9361deefb7c8dcf2b329298e959c102e07712cddac67e367af1963b13b8cec1123f977baa3778f17831dc1c0244c381a77ca3b4d7fce62b4a876e645567f0eab17ae4ebbb4b13370d4e41f78b196e7162e6ba3106d36d83a26841f415a0e4d710aa4f6e7c2acfa73bb2899c75e87dda3946f5960167e88180b193c189ab6a1fc554854962c417108f16d3217586e16c643c2b3278bf5b4fbaebdab9a53ec65a096a2323d65581735080b51d6d502831481fddfefe864c8b502aee962e6fc4d50e986bb342a9b2d44c428f786e0d78e48be6bab041732a5a22f76d24af52138efbc2599120963182a6d1ed73d9b99c88d615898b7cb9c2ef30e36ade7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87847);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-6431");
  script_bugtraq_id(79654);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux48405");
  script_xref(name:"CISCO-SA", value:"cisco-sa-2015-1221-iosxe");

  script_name(english:"Cisco IOS XE Source MAC Address DoS (CSCux48405)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is Release 16.1.1. It is, therefore,
affected by a denial of service vulnerability due to incorrect
processing of packets that have 0000:0000:0000 as a source MAC
address. An unauthenticated, adjacent attacker can exploit this to
cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-2015-1221-iosxe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38f90004");
  script_set_attribute(attribute:"see_also", value:"https://quickview.cloudapps.cisco.com/quickview/bug/CSCux48405");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6431");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;

# Check for the single vulnerable version
# 16.1.1
if (
  ver =~ "^16\.1\.1$"
)
{
  flag++;
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCux48405' +
      '\n  Installed release : ' + ver +
      '\n';
    security_warning(port:0, extra:report );
    exit(0);
  }
  else security_warning(port:0);
}
else audit(AUDIT_HOST_NOT, "affected");
