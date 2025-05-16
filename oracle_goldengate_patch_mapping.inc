###                                                                                                                                      
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# oracle_webcenter_goldengate_mapping.inc
#
# Revision: 1.14
#
###

var goldengate_version_map = make_array(
    #January 2025
    '19.26.0.0.250121', make_list('37477750'),

    # November 2024
    '19.25.0.0.241015', make_list('37071121'),
    '19.25.0.0.241105', make_list('37236684'),
    
    # July 2024
    '19.24.0.0.240716', make_list('36798114', '36798115', '36798116', '36798117'),
    '21.15.0.0.0', make_list('36797866'),

    # May 2024 (replaced 19.23.0.0.240416 patches due to regression issues)
    '19.23.0.0.240526', make_list('36661502', '36661503', '36661504', '36661505'),

    # April 2024
    '19.23.0.0.240416', make_list('36475235', '36475236', '36475237', '36475238'),
    '21.14.0.0.0', make_list('36473479'),

    # January 2024
    '19.22.0.0.240116', make_list('36176773', '36176774', '36176775', '36176776'),
    '19.22.0.0.240124', make_list('36238779', '36238780', '36238781', '36238782'),
    '21.13.0.0.0', make_list('36175509'),

    # October 2023
    '19.21.0.0.231017', make_list('35875756', '35875757', '35875758', '35875759'),
    '21.12.0.0.0', make_list('35896243'),

    # July 2023
    '19.20.0.0.230718', make_list('35580167', '35580175', '35580178', '35580180'),
    '21.11.0.0.0', make_list('35576640', '35577874'),

    # May 2023
    # https://support.oracle.com/epmos/faces/DocumentDisplay?_afrLoop=206037205648800&parent=DOCUMENT&sourceId=1645495.1&id=2947665.1&_afrWindowMode=0&_adf.ctrl-state=12i6hqlh76_126
    # https://support.oracle.com/epmos/faces/DocumentDisplay?_afrLoop=206847492460817&parent=DOCUMENT&sourceId=1645495.1&id=2947708.1&_afrWindowMode=0&_adf.ctrl-state=12i6hqlh76_175
    '19.1.0.0.230422', make_list('35326251', '35326271', '35326273', '35326279', '35326289', '35326294', '35326299', '35326305'),

    # April 2023
    '19.1.0.0.230418', make_list('35275310', '35275313', '35275317', '35275319'),
    '21.10.0.0.0', make_list('35271070', '35271078', '35271084'),

    # Jan 2023 (No CPU)
    '19.1.0.0.230117', make_list('34961902', '34961903', '34962405', '34962407'),
    '21.9.0.0.0', make_list('34958358', '34958363'),

    # October 2022
    '19.1.0.0.221018', make_list('34648537', '34653308', '34653311', '34653323'),
    '21.8.0.0.0', make_list('34686059', '34686071'),

    # July 2022
    '19.1.0.0.220719', make_list('34377350', '34377368', '34377377', '34377379'),
    '21.7.0.0.0', make_list('34315139', '34315141'),

    # January 2022
    '19.1.0.0.220118', make_list('33742655', '33742660', '33742664', '33742666'),
    '21.5.0.0.2', make_list('33833650', '33833656'),

    # October 2021
    '19.1.0.0.211019', make_list('33376981', '33376978', '33376975', '33376964'),
    '21.4.0.0.0', make_list('33430250', '33469293'),

    # February 2020
    '12.2.0.2.200218', make_list('30619259'),

    # October 2019
    '12.3.0.1.191015', make_list('30341565'),

    # October 2018
    '12.1.2.1.181016', make_list('28696808', '28696813'),
    '12.2.0.2.181009', make_list('28651607', '28651610'),
    '12.3.0.1.180821', make_list('28498482', '28498505'),

    # April 2018
    '12.2.0.1.161018', make_list('24765017', '24764985', '24764950', '24764941')
);
