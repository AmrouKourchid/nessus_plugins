#TRUSTED 48a2ba51877f987fef7fe869a106942c179bc30fdeebe1648cefc352f28d9de2e365b40e16f3d33f88cebb544ad442578e4ff4099cb828a0cb8a3dee037da7ef20fa2d896e4191f29bf8e77a5d6e5111ae9ccedd20e6ecf852a51977a6e241e079c80915883cd3b16964cc8fc2b1d71bb570995319fcb5c0bd1d34ea12d667f8847ef94e06b4b8131afe32f74436d01a375dd0f25e16fa7b8bb977c05992132730007be1b75d96bc1e501dc4af74561656855b5790b960d199f275e5cfc6af0fe52b2197585a93c5c9e7b4a153f82f868f65fda10627fa699e924d131812cc35ebe54b3c09c82031052cdb11e042e6a2d184057404e536eaecd2b83f71593a0b9ac3b05207e75adfa99f8a3221babf676b5131ab7c3b27608155d648dc7a99ea1884509d40523825e2ce1e107827ea0ec3e321cbeb55601efb22690b553d25c02c1df265df2c99561281dca4d7d67de083c0e2a62ad5c01eec588fc321fb8d4154e69e342d618e8acec26caa7e34da7c54e93ce36d1b797c207510b25e4bff1bf430c13def5875f1ab32ff699f2fb40764698d06be29bd65af31bb233a6ba4d448c2199ac383627b6ca6248884c435391e5e0d9797aeff8d1a763592ccf10183a993771d91143f56e8f7cc0f65fcf48b0c11f859bd7e9cac8ef95f4902ad66d1ba0950fcd5bbe15c325622a55d562781287a39157019a1909d9dbc17d4bb74f7
#TRUST-RSA-SHA256 967a0605e1be9dc71f0553f3169ca8f8f0c91d547507a8aad431ccf477fbdcf8a4f88a5e7cca97c4858effb2e0043572d5257a78b8311789c4c099e45a048ba86c86feb8abca24da4721f91584badd9b0427b01f20f1ac85a4516f440e1d7b51b55c27005b2020a2f005cb99311c5269675f0732b09d1ed6279422781b8dee986d6e064bd8bc2a0afaa48ae3b455e996ed1b86804df14fa5aeb9fd9f425ae006fc33bd2c96533f77de9ad04e7be3fad31c4de87286e828a47514c7f32aeb5cd69bba983b70b5817faa9d4807c6393b182b0aefd1655632d8152ab1ee0e676d2e6561334ad99578877eb3416c1cf53b258b92d73bc2c8544541b4006ef122747299c410a1e2eb6434ebf4295113cf2c4365730670098c654d83bb2f601afba15fbe4927aca0a420b924f752b1354d90a8523fb3b99cacb12548419086bdbbb16fc88b8f54fd9e3be26d6e4a48fece28ea6a78886a2d685f97cdc601abf61c4df81f339c25acea14fb0205ba5bbb793eb57295c9ac3bf1c3c425a41e3ddd37150b7c8c5a427b6204bf7e73358273ac9656e6b19d012b611f9c17a429d798de5601d11f97d2d35678d8d580949db8f0d0be4a7db04054f3839be468a865662d6de0a4fdba141df0967b631c5622edbcfebcdf98d271ed5ee9a1d3f0a0d78812949ae31e6244e3202bbe71fce3add0f264442c330f7a049f5a46cb32fe01b55a3283
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35685);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2008-2086",
    "CVE-2008-5340",
    "CVE-2008-5342",
    "CVE-2008-5343"
  );
  script_bugtraq_id(32892);

  script_name(english:"Mac OS X : Java for Mac OS X 10.4 Release 8");
  script_summary(english:"Check for Java Release 8 on Mac OS X 10.4");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS X
older than release 8. 

The remote version of this software contains several security
vulnerabilities in Java Web Start and the Java Plug-in.  For instance,
they may allow untrusted Java Web Start applications and untrusted Java
applets to obtain elevated privileges.  If an attacker can lure a user
on the affected host into visiting a specially crafted web page with a
malicious Java applet, he could leverage these issues to execute
arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3436");
  # http://lists.apple.com/archives/security-announce/2009/Feb/msg00002.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?383310c3");
  script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.4 release 8.");
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


# Mac OS X 10.4.11 only.
uname = get_kb_item("Host/uname");
if (egrep(pattern:"Darwin.* 8\.11\.", string:uname))
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

  # Fixed in version 11.8.2.
  if (
    ver[0] < 11 ||
    (
      ver[0] == 11 &&
      (
        ver[1] < 8 ||
        (ver[1] == 8 && ver[2] < 2)
      )
    )
  ) security_hole(0);
}
