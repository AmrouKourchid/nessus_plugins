##
#%NASL_MIN_LEVEL 80900
## (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/12/12. Advisory removed from OVAL
##

include('compat.inc');

if (description)
{
  script_id(184119);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/15");

  script_cve_id("CVE-2023-4039");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:4287-1");

  script_name(english:"SUSE SLES12 Security Update : gcc13 (SUSE-SU-2023:4287-1) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The advisory referenced by this plugin has been recalled from the OVAL, so this 
plugin has been deprecated.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214460");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-October/016953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58f57f6f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4039");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4039");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cpp13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-nvptx-gcc13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-nvptx-newlib13-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc13-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc13-PIE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc13-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc13-c++-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc13-fortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc13-fortran-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc13-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc13-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan8-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgomp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgomp1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhwasan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libitm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libitm1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liblsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libobjc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libobjc4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libquadmath0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libquadmath0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-devel-gcc13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-devel-gcc13-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-pp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-pp-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtsan2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan1-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}

exit(0, 'This plugin has been deprecated because the advisory has been recalled from the OVAL.');
