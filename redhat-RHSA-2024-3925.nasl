#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:3925. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200554);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2023-3128",
    "CVE-2023-4822",
    "CVE-2023-49568",
    "CVE-2023-49569"
  );
  script_xref(name:"RHSA", value:"2024:3925");

  script_name(english:"RHEL 8 / 9 : Red Hat Ceph Storage 7.1 (RHSA-2024:3925)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:3925 advisory.

    Red Hat Ceph Storage is a scalable, open, software-defined storage platform that combines the most stable
    version of the Ceph storage system with a Ceph management platform, deployment utilities, and support
    services.

    These new packages include numerous enhancements, bug fixes, and known issues. Space precludes documenting
    all of these changes in this advisory. Users are directed to the Red Hat Ceph Storage Release Notes for
    information on the most significant of these changes:

    https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/7.1/html/release_notes/index

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-3128");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-49568");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-49569");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-4822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1871333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1954461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1954463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1995152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2009599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2029585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2061627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2068026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2068030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2079815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2079897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2089167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2112325");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2125107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2130292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2134786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2144472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2148831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2149450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2153468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2166576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2172162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2176297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2185792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2190366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2207713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2213626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2213766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2217499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2227309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2227314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2233659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2235753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2240138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2240583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2242431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2243105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2243626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2244417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245261");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2248639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2248855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2249003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2249068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2249518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2249573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2249651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2249744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2249812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2251004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2251192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2252048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2252396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254121");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254122");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2256560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2256967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2259179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2259461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2259938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2260003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2260835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2261239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2263813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2263898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2263990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269321");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270402");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271110");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279352");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283630");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_3925.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eda09809");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:3925");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-49569");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 305, 400);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-immutable-object-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephadm-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephfs-top");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gperftools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gperftools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:liboath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libradospp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libunwind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oath-toolkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-nbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thrift");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','9'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/ppc64le/rhceph-tools/7/debug',
      'content/dist/layered/rhel8/ppc64le/rhceph-tools/7/os',
      'content/dist/layered/rhel8/ppc64le/rhceph-tools/7/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhceph-tools/7/debug',
      'content/dist/layered/rhel8/s390x/rhceph-tools/7/os',
      'content/dist/layered/rhel8/s390x/rhceph-tools/7/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhceph-tools/7/debug',
      'content/dist/layered/rhel8/x86_64/rhceph-tools/7/os',
      'content/dist/layered/rhel8/x86_64/rhceph-tools/7/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ceph-base-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-base-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-common-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-common-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-fuse-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-fuse-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-immutable-object-cache-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-immutable-object-cache-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-mib-18.2.1-194.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-resource-agents-18.2.1-194.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-selinux-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-selinux-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'cephfs-top-18.2.1-194.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'gperftools-libs-2.7-9.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-4822']},
      {'reference':'gperftools-libs-2.7-9.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-4822']},
      {'reference':'libcephfs-devel-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libcephfs-devel-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libcephfs2-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libcephfs2-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'liboath-2.6.2-3.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-', 'cves':['CVE-2023-4822']},
      {'reference':'liboath-2.6.2-3.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-', 'cves':['CVE-2023-4822']},
      {'reference':'librados-devel-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librados-devel-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librados2-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librados2-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libradospp-devel-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libradospp-devel-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libradosstriper1-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libradosstriper1-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librbd-devel-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librbd-devel-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librbd1-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librbd1-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librgw-devel-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librgw-devel-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librgw2-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librgw2-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libunwind-1.3.1-3.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-', 'cves':['CVE-2023-4822']},
      {'reference':'python3-ceph-argparse-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-ceph-argparse-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-ceph-common-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-ceph-common-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-cephfs-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-cephfs-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rados-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rados-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rbd-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rbd-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rgw-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rgw-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'rbd-nbd-18.2.1-194.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'rbd-nbd-18.2.1-194.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'thrift-0.13.0-2.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-', 'cves':['CVE-2023-4822']},
      {'reference':'thrift-0.13.0-2.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-', 'cves':['CVE-2023-4822']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/ppc64le/rhceph-tools/7/debug',
      'content/dist/layered/rhel9/ppc64le/rhceph-tools/7/os',
      'content/dist/layered/rhel9/ppc64le/rhceph-tools/7/source/SRPMS',
      'content/dist/layered/rhel9/s390x/rhceph-tools/7/debug',
      'content/dist/layered/rhel9/s390x/rhceph-tools/7/os',
      'content/dist/layered/rhel9/s390x/rhceph-tools/7/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhceph-tools/7/debug',
      'content/dist/layered/rhel9/x86_64/rhceph-tools/7/os',
      'content/dist/layered/rhel9/x86_64/rhceph-tools/7/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ceph-base-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-base-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-base-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-common-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-common-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-common-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-fuse-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-fuse-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-fuse-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-immutable-object-cache-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-immutable-object-cache-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-immutable-object-cache-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-mib-18.2.1-194.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-resource-agents-18.2.1-194.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-selinux-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-selinux-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'ceph-selinux-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'cephadm-18.2.1-194.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'cephadm-ansible-3.2.0-1.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-4822']},
      {'reference':'cephfs-top-18.2.1-194.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libcephfs-devel-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libcephfs-devel-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libcephfs-devel-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libcephfs2-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libcephfs2-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libcephfs2-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librados-devel-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librados-devel-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librados-devel-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librados2-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librados2-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librados2-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libradospp-devel-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libradospp-devel-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libradospp-devel-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libradosstriper1-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libradosstriper1-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'libradosstriper1-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librbd-devel-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librbd-devel-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librbd-devel-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librbd1-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librbd1-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librbd1-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librgw-devel-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librgw-devel-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librgw-devel-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librgw2-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librgw2-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'librgw2-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-ceph-argparse-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-ceph-argparse-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-ceph-argparse-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-ceph-common-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-ceph-common-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-ceph-common-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-cephfs-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-cephfs-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-cephfs-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rados-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rados-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rados-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rbd-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rbd-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rbd-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rgw-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rgw-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'python3-rgw-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'rbd-nbd-18.2.1-194.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'rbd-nbd-18.2.1-194.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']},
      {'reference':'rbd-nbd-18.2.1-194.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2023-3128', 'CVE-2023-4822', 'CVE-2023-49568', 'CVE-2023-49569']}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    var cves = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph-base / ceph-common / ceph-fuse / ceph-immutable-object-cache / etc');
}
