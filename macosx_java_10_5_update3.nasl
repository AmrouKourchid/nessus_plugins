#TRUSTED 7b97b06976f13ee38c6d12b0d315c3c6283fdce90533c5c145446525464663a5cc558d721b5781b458def14eab03b32af63efa3d51b9dff2a48479a7cf40fbbfc9044718f22bda38e476963cfd5f8aaf001979a49e7f2930d238e2ececb894d3fa1083915b4fc3ac96aebac022fb8517add85f150bf1b8bfa31e60fe3a8037668cc5dc87da397f7768fcac46760629bc54d89535ca7b7ede44b8e5820578b03565aac3abbc8ad2bf18d19a531c67fb8565e823f5f0930379df8ca0568518bccf843c3bd7404dfa9abaae44a7cdf0cd1856d0debc0235ee43ee89221e1fab4570e7af9afefddc78e90755213cd568c0eff4d735bdd776faa5a6041e5f821ffe09cb83641d0a281cde66c04a8e359472643b1271613cd28d68174e9c090ac0fd37361b87494b94c5547a3e0f1f8c7c8b11071b678b0765872eab1d917515e0d834aa901337f812c3f37ff8a5b4ebf4f80d458fec02596bea98e035b1b599feae781cb6c905c60eb33d99292141ab5f4b148cc3a9c27c74a6aa6314b88b7c2ff865b156d49d5891a7e0e2541888ef67d0cc9466da3a1a552fef02e6941d939e44301577b2b47985029b845f79bf2d6968165a1e5b7489bfaad4aeb56ac0d72147133ffcd118b49a275a549252a17dc0e990bf5e3b95c79b2f6cdfda8d0cda588a18a87e9cc4d43df0101ed205a1ba520f95f7df8c798c24e44f889e861f701c6f8e
#TRUST-RSA-SHA256 81339a1e67140dfa99f532208bbf84b749c8b4d441ee5aa639ca632bed0311c837e04a909ad0c85e14a87d451b1e74981bb5a2738e62a649561b8310fd13ad9b28ee7ae25a5c63b39f859398cb5e22d7fc8a6eb03c36031470c5ea3d58ecdbabe27cdfa20246fb916068979de804d1638ee49b992d2234a58987ae298295a0ca5730484196edcffa8782dcf67217eceffa4211f10db8e9006a6666898a7fda65a52462cc8c4700eedcb65681a36fa04486c01e2a73908146d673cd63c31c365ba179d6d6a3788ddd08165af137fab727b4d9e57a329b8f0e10e56c8c01cee21bfd61ebfec13afc44e57cd3a8b654bb9f8535b371cf90f182357b2ee97233481f4c21db266bc00a454ce78bd6c41ca6fd359b1e2ccd2334681ea2ff2c005eed7b02660b7cbebe2195232f6336e09d8c2a95d921106d7070d7eb6ee59ded7313bb9977005192dc3f32597d3e9228b2be75c63132ee91c1618abe8f0cec408853d87a53a4527818bdede606f4ee753748b3981fe45fd3e59dc681b0021b21e9bfd6c8bd859970f2368733644736bcdf85cbd98377e379424556a71747a33a601d64fee9a9b8209157282008a8c225976e03d9c31d8f02c21972adabec7dfb6d5927bb3ae84b4f6af9c7b86c1ef8ffb405d5cad7b1264a045da8c1ba6654bee3d385dd46ce3ec2484f8b4ab702d423d569a61d57f09c9087e000ac77af487756cd52
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35686);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2008-2086",
    "CVE-2008-5340",
    "CVE-2008-5342",
    "CVE-2008-5343"
  );
  script_bugtraq_id(32892);

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 3");
  script_summary(english:"Checks for Java Update 3 on Mac OS X 10.5");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:"
The remote Mac OS X 10.5 host is running a version of Java for Mac OS X
that is missing Update 3. 

The remote version of this software contains several security
vulnerabilities in Java Web Start and the Java Plug-in.  For instance,
they may allow untrusted Java Web Start applications and untrusted Java
applets to obtain elevated privileges.  If an attacker can lure a user
on the affected host into visiting a specially crafted web page with a
malicious Java applet, he could leverage these issues to execute
arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3437");
  # http://lists.apple.com/archives/security-announce/2009/Feb/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce3083d5");
  script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.5 Update 3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-5340");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

if (!defined_func("bn_random")) exit(0);

include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


enable_ssh_wrappers();

function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = info_connect();
    if (!ret) exit(0);
    buf = info_send_cmd(cmd:cmd);
    if (info_t == INFO_SSH)
      ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(0);

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0);


# Mac OS X 10.5 only.
uname = get_kb_item("Host/uname");
if (egrep(pattern:"Darwin.* 9\.", string:uname))
{
  plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
  cmd = string(
    "cat ", plist, " | ",
    "grep -A 1 CFBundleVersion | ",
    "tail -n 1 | ",
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
  );
  version = exec(cmd:cmd);
  if (!strlen(version)) exit(0);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 12.2.2.
  if (
    ver[0] < 12 ||
    (
      ver[0] == 12 &&
      (
        ver[1] < 2 ||
        (ver[1] == 2 && ver[2] < 2)
      )
    )
  ) security_hole(0);
}
