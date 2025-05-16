#TRUSTED 799b00b7e20d65c7cb59e9d041a1a6870c5f5fd66b39fb473441251a88df4430e8ce8e22b6910fd45674b94392b7a0cf69cdaef6825d95f06d69d96ab308e08b32946b33ba932ea824b47bd099aa6cd72854bea4c9a90bc95fa0d57be72246f110e2d0c5f6414a46bb32f3f4739454e686034e9e0a056461caea412c3dc15c7ce752fbbabe0ec79c7e6c40aa5e0a1e4ad0f1313dbe1ce3d2ce408bb8c53f99b7614402077876edce12ca7d3957bf7d2f266f4eb942a185a5e11cc8011ed8eab185a36ad63af665bda39c8090389b4e4891da8c62d6d5d75ee4872d19b336ef398f65af8da4bc94a5fbf2a8b228f138b52687138c0871fcf906a5754f715e06a12ef07836b7590315e6de7fe27e788500e96c4eea4f1c6655d2582d5c1a52d7d7591883682c61d8c661c4e8f6dee9b095b0afe0cb6e3ebe9619b3599f9e03d5ac96acd502f78268f0f15d94b4d79716bddc6ddb2b6e6d454cfe7bf521e8c71c8cc9c2da5b94db3ccff9bebd33cd9e7a8e8b8c495ef48d945478d598ded95cd8639f9c2dac8679e172dd8c8b9fc0a64cca6c942f60be1719a4bf9d7c0b05498fe98ff3ba15514722dda7336f3491a52d4589f7d3e9f2503448c05c640ab3cb1170a5177807935f166ede7d763d76baba0223665b340ca2002fa5a99723a03595ddefac3ce0a4b89eaa797eaa3ee8484bb6003b46666f1973638acaa653bfdfd3b6
#TRUST-RSA-SHA256 28bab262eb3bdb003402440e4bd3d99eb917de2e7a334420ea84a345640737d4101baad17a172352b4afa1c1e47768c7bf2c61e5b972ff1c8d684e5d6cce09c5b26182845a2457d417a3af30f9a7662cec3ba6554e93bc90997ed298f77b5d8fce3d1cd8e43a457c2f6b6cd207200cc7374402adbf61a2740f4e8335c0dcff8e044fc0a1ce4264069ed6e6309cf96d9409c76f09a00364ca21fa89e2d2e01517d6c71744dc62e3ee2f49f9f9e53292fcf7e78bfb8a4d09cb5296ebe43cd889ef3463c8e8d2a4886becee25dc3e8950d38e23e7bf9b833d7c25d8605cee47310acc59a1807d7b85f430837f7725dd526e4d5b61985952ff85ce993c03cb1cd861caee4cc3f631e8319a70962431148e2785f0bb4cf73f0a42ff70d0912c02bb29829fc37f558997333f4a84e511a77813763c7eeb3ba643b719373659d56c7435ea3b07088b50da293d744a02de6cb15f6b8d46be2ccdd979acba7389d75ce7ed2c69853da9817e4c5ce7b984c07c03aa3a3ec49e09a1b392482c6d0b7c194332bb2e1596f44dce6c8ddcf94f12b2d584becd509e20691222f958c9d4152ff7fcaaeee3ef718a6545e7e64d36e467aa19456225df407ec469bdd1efe33b8010a0dbde5acf2b68a9020bd6cbb626a97375edca2f48bf7f24c459ccc9216e643603f42cbf67264d7103c7fe86fd1bad2dae2973c5b49d3141abb99d2cf80e5e5701
#
# (C) Tenable Network Security, Inc.
#
#

include("compat.inc");

if (description)
{
  script_id(30201);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2008-0043");
  script_bugtraq_id(27636);

  script_name(english:"iPhoto < 7.1.2 Format String Vulnerability");
  script_summary(english:"Checks version of iPhoto");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by a
format string vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of iPhoto 7.1 older than version
7.1.2. Such versions are reportedly affected by a format string
vulnerability. If an attacker can trick a user on the affected host
into subscribing to a specially crafted photocast, these issues could
be leveraged to execute arbitrary code on the affected host subject to
the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307398");
  # http://lists.apple.com/archives/security-announce/2008/Feb/msg00000.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35e83984");
  script_set_attribute(attribute:"see_also", value:"http://www.apple.com/support/downloads/iphoto712.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to iPhoto 7.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2008-0043");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0043");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:iphoto");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2008-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

if (!defined_func("bn_random")) exit(0);

include("global_settings.inc");
include("macosx_func.inc");
include("misc_func.inc");
include("ssh_func.inc");


enable_ssh_wrappers();

uname = get_kb_item("Host/uname");
if (!uname) exit(0);

if (egrep(pattern:"Darwin.*", string:uname))
{
  cmd = GetBundleVersionCmd(file:"iPhoto.app", path:"/Applications");
  if (islocalhost())
    version = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = info_connect();
    if (!ret) exit(0);

    version = info_send_cmd(cmd:cmd);
    if (info_t == INFO_SSH)
      ssh_close_connection();
  }

  if (version)
  {
    version = chomp(version);
    ver = split(version, sep:'.', keep:FALSE);

    #Prevent FPs if shell handler errors get mixed into results
    if(int(ver[0]) == 0 && ver[0] != "0") exit(1, "Failed to get the version of GarageBand.");

    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (
      ver[0] == 7 &&
      (
        ver[1] == 0 ||
        (ver[1] == 1 && ver[2] < 2)
      )
    )
    {
        report = string(
          "\n",
          "The remote version of iPhoto is ", version, ".\n"
        );
        security_hole(port:0, extra:report);
    }
  }
}
