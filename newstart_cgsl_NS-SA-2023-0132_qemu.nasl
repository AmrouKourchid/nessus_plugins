#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/12/04 due to vendor advisory.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0132. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185386);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/04");

  script_cve_id(
    "CVE-2019-12068",
    "CVE-2019-15890",
    "CVE-2020-1711",
    "CVE-2020-14364",
    "CVE-2021-3682",
    "CVE-2021-3713",
    "CVE-2023-1544"
  );
  script_xref(name:"IAVB", value:"2020-B-0063-S");
  script_xref(name:"IAVB", value:"2023-B-0058-S");

  script_name(english:"NewStart CGSL MAIN 6.06 : qemu Multiple Vulnerabilities (NS-SA-2023-0132) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2023-0132");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-12068");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-15890");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-14364");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-1711");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3682");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3713");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1544");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated.");
