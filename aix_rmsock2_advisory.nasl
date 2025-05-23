#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(110777);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/22");

  script_cve_id("CVE-2018-1655");
  script_bugtraq_id(104542);
  script_xref(name:"IAVA", value:"2018-A-0199-S");

  script_name(english:"AIX rmsock Advisory : rmsock_advisory2.asc (IJ06904) (IJ06905) (IJ06906) (IJ06907) (IJ06908) (IJ06934) (IJ06935)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of the rmsock command installed
that is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the rmsock command installed on the remote AIX host is
affected by an information disclosure vulnerability. An unauthenticated,
local attacker can exploit this and potentially expose kernel memory.");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/rmsock_advisory2.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item("Host/AIX/version");
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevel = oslevel - "AIX-";

oslevelcomplete = chomp(get_kb_item("Host/AIX/oslevelsp"));
if (isnull(oslevelcomplete)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevelparts = split(oslevelcomplete, sep:'-', keep:0);
if ( max_index(oslevelparts) != 4 ) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
ml = oslevelparts[1];
sp = oslevelparts[2];

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

aix_bind_vulns = {
  "5.3": {
    "12": {
      "09": {
        "bos.net.tcp.client": {
          "minfilesetver":"5.3.12.0",
          "maxfilesetver":"5.3.12.10",
          "patch":"(IJ06935s1a)"
        }
      }
    }
  },
  "6.1": {
    "09": {
      "11": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.315",
          "patch":"(IJ06905s9a)"
        }
      }
    }
  },
  "7.1": {
    "04": {
      "06": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.33",
          "patch":"(IJ06906s4a)"
        }
      }
    },
    "05": {
      "02": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.5.0",
          "maxfilesetver":"7.1.5.15",
          "patch":"(IJ06904s5a)"
        }
      }
    }
  },
  "7.2": {
   "00": {
      "06": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.3",
          "patch":"(IJ06934s0a)"
        }
      }
    },
    "01": {
      "04": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.1.0",
          "maxfilesetver":"7.2.1.3",
          "patch":"(IJ06907s1a)"
        }
      }
    },
    "02": {
      "02": {
        "bos.net.tcp.client_core": {
          "minfilesetver":"7.2.2.0",
          "maxfilesetver":"7.2.2.16",
          "patch":"(IJ06908s2a)"
        }
      }
    }
  }
};

version_report = "AIX " + oslevel;
if ( empty_or_null(aix_bind_vulns[oslevel]) ) {
  os_options = join( sort( keys(aix_bind_vulns) ), sep:' / ' );
  audit(AUDIT_OS_NOT, os_options, version_report);
}

version_report = version_report + " ML " + ml;
if ( empty_or_null(aix_bind_vulns[oslevel][ml]) ) {
  ml_options = join( sort( keys(aix_bind_vulns[oslevel]) ), sep:' / ' );
  audit(AUDIT_OS_NOT, "ML " + ml_options, version_report);
}

version_report = version_report + " SP " + sp;
if ( empty_or_null(aix_bind_vulns[oslevel][ml][sp]) ) {
  sp_options = join( sort( keys(aix_bind_vulns[oslevel][ml]) ), sep:' / ' );
  audit(AUDIT_OS_NOT, "SP " + sp_options, version_report);
}

foreach package ( keys(aix_bind_vulns[oslevel][ml][sp]) ) {
  package_info = aix_bind_vulns[oslevel][ml][sp][package];
  minfilesetver = package_info["minfilesetver"];
  maxfilesetver = package_info["maxfilesetver"];
  patch =         package_info["patch"];
  if (aix_check_ifix(release:oslevel, ml:ml, sp:sp, patch:patch, package:package, minfilesetver:minfilesetver, maxfilesetver:maxfilesetver) < 0) flag++;
}

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bos.net.tcp.client / bos.net.tcp.client_core");
}
