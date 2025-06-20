#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2025-02-12.
# Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory thunderbird. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(199882);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2016-5823");

  script_name(english:"RHEL 6 : thunderbird (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9398.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fd036b2");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9394.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c329a33");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9396.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a7e3e79");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-48949.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42b045e5");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9393.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?443af80c");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9400.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66887bd5");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9399.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83e7037f");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9401.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8745a918");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9403.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?942651e4");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9402.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c09009e9");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9397.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ced1ba26");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9392.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eaf0c5aa");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5823");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
