#TRUSTED 657bb98cebf6373f11302da8ba105be266cc4d80d9cfb4ad91557920a9dfd554d0ffae5d5bca129298402980d69eabceed8bed9e4c247ca88f357cd18ca5c5cc83711d5eeb825cbeb9aa78b83863ac1851c16ec87d8e4762454e9afeeab86ada1f915c6d05b397fa44012a76afec1ea6541498b2afd43a87879985ebee81b538975abbccd825e81cf73822db57084b0eb282520fc18d0306c5f536dd828bbe0b95718377c3bdd5c33aa67a75827107338d8bc3d1ef1500a2c123f53f8b1c3dfd39d4e3e92a897ef0771296b55dd23f7013bcc0fd7d2f43a5a95de483be26e76a4ee961ad9e28df0c8b9cbea0603ee36206f6598c3245567eb5b65f134f26a4c8de24d94b41e02e396dbb8614d6b95b2d4e60f7fea0fe1329f95ec4073c3cf61c6ffd89877e7b62bffe373c039f9f8e7e6d51ea6e6d9512b5c690f8fa6c11988f1cd2ffc4fe1366ae498e0a7396fc541e77a75c9d4c1a9dd82a447a5aeea54e310a5c1fa7a4809c42cfb6cad39551bf88fa27194de24da8afded5db9a4843585b2ec175633baa0d47ca3d565b8a288103d6802dc77c79a5e6bcb03ec296b17e5d3af8e2820cbbc13616c9c60cecca6547a2e4295977b83170aa26347eebae286cebd10585161dfedeae51903833210045ad628018e4a43e45b95952c2eb2c21388eddecea60f03fcb1e6f8c77cdfff93eb2110f4669c129a3b8b8a827257c599b
#TRUST-RSA-SHA256 505638b995790dfba46c0f5abe7da5a2c917d18a780336168572787c508b98afb66c27da74947bcbb2f756e3c34ce27b4c43b4b5922a0a134054e72239c283bfef0153ae6bcbe0cd94fb70206457f268eca2e1faa8a9a25891c65c2c01b069a53e4840bc53a28904ab9f884356e7aa7ae810d800c6549dc1698423ce2aad8f3be73709a30d6ee9c345fc21efb5015787b31eed7b1c0bd6262aa93114025d39241c4a4740207abdba70647f7c8ebda4bfcc2e4646fe91186a78ee48d0401c30798fe5e04f0741a41f7432b4479945f462e817419f4d045d0f530b16dc80bc4a51a83036e3466ce8d13fd3a57c7dee5dfe7944c229ef0884ee2df546642eebf9a5135511808123c547fea12c4acef7070fe7ed814ea8f9c9fc71d2662929de163053621f8447849c235f50b7991b94b8c4af1e48ce3af3c50410fb116294ae23cc23678269006647fb8af39a74ea59fedcbed721de076fe5a07e9964b282f859d6333d36bbd9b03d7726935889f03889a0e3a9c8055aa39d14eb377e35f1b0178ce4bddabc47958fe871d30b5817cc1813db9b16b89b581445f9b32f879b178e2996ebb6d0c3ae756932e18ef7dbc071d8d7b13493fda703c89b12b9da6fb47e3d3b601886547ca165ee268d61880a2b98c657278fb46005360b42080076d5f044af63f5236bbe45ef504248766985b112f2998c95ca4c143d6db3d44c02e12752
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40873);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2009-0217",
    "CVE-2009-2205",
    "CVE-2009-2475",
    "CVE-2009-2476",
    "CVE-2009-2625",
    "CVE-2009-2670",
    "CVE-2009-2671",
    "CVE-2009-2672",
    "CVE-2009-2673",
    "CVE-2009-2674",
    "CVE-2009-2675",
    "CVE-2009-2689",
    "CVE-2009-2690",
    "CVE-2009-2722",
    "CVE-2009-2723"
  );
  script_bugtraq_id(35671, 35939, 35942, 35943, 35958);

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 5");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.5 that is missing Update 5.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3851"
  );
  # http://lists.apple.com/archives/security-announce/2009/Sep/msg00000.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57823afa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/17819"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.5 Update 5 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-2723");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

function exec(cmd)
{
  local_var buf, ret;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = info_connect();
    if (!ret) exit(1, "info_connect() failed.");
    buf = info_send_cmd(cmd:cmd);
    if (info_t == INFO_SSH)
      ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(1, "Failed to get the version - '"+buf+"'.");
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");


# Mac OS X 10.5 only.
if (!egrep(pattern:"Darwin.* 9\.", string:uname)) exit(0, "The remote Mac is not affected.");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd = string(
  "cat ", plist, " | ",
  "grep -A 1 CFBundleVersion | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 12.4.1.
if (
  ver[0] < 12 ||
  (
    ver[0] == 12 &&
    (
      ver[1] < 4 ||
      (ver[1] == 4 && ver[2] < 1)
    )
  )
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.4.1\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
