#
# Copyright (c) 2013-2018 Quarkslab.
# This file is part of IRMA project.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the top-level directory
# of this distribution and at:
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# No part of the project, including this file, may be copied,
# modified, propagated, or distributed except according to the
# terms contained in the LICENSE file.

import asynctest
import logging
from pathlib import Path
import re
import time
from irmacl_async.apiclient import AAPI


SCAN_TIMEOUT_SEC = 3000
BEFORE_NEXT_PROGRESS = 5
EICAR_NAME = "eicar.com"
EICAR_PATH = Path(__file__).parent / "samples" / EICAR_NAME
EICAR_HASH = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
MAXTIME_SLOW_PROBE = 60
MAXTIME_NORMAL_PROBE = 30
MAXTIME_FAST_PROBE = 10
NOT_CHECKED = "This value is not checked"
EICAR_RESULTS = {
    "antivirus": {
        "AVG AntiVirus Free (Linux)": {
            "status": 1,
            "results": "EICAR_Test",
            "version": "13.0.3114",
            "duration": MAXTIME_NORMAL_PROBE,
        },
        "Avast Core Security (Linux)": {
            "status": 1,
            "results": "EICAR Test-NOT virus!!!",
            "version": "2.1.1",
            "duration": MAXTIME_NORMAL_PROBE,
        },
        "Avira (Linux)": {
            "status": 1,
            "results": "Eicar-Test-Signature",
            "version": "1.9.150.0",
            "duration": MAXTIME_NORMAL_PROBE,
        },
        "Bitdefender Antivirus Scanner (Linux)": {
            "status": 1,
            "results": r"EICAR-Test-File \(not a virus\)",
            "version": "7.141118",
            "duration": MAXTIME_NORMAL_PROBE,
        },
        "Clam AntiVirus Scanner (Linux)": {
            "status": 1,
            "results": "Eicar-Test-Signature",
            "version": "0.99.2",
            "duration": MAXTIME_NORMAL_PROBE,
        },
        "Comodo Antivirus (Linux)": {
            "status": 1,
            "results": "ApplicUnwnt",
            "version": "1.1.268025.1",
            "duration": MAXTIME_NORMAL_PROBE,
        },
        "DrWeb Antivirus (Linux)": {
            "status": 1,
            "results": r"EICAR Test File \(NOT a Virus!\)",
            "version": "10.1.0.1.1507091917",
            "duration": MAXTIME_SLOW_PROBE,
        },
        "Eicar Antivirus (Linux)": {
            "status": 1,
            "results": r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!",
            "version": "1.0.0",
            "duration": MAXTIME_FAST_PROBE,
        },
        "Emsisoft Commandline Scanner (Windows)": {
            "status": 1,
            "results": r"EICAR-Test-File \(not a virus\) \(B\)",
            "version": "12.2.0.7060",
            "duration": MAXTIME_FAST_PROBE,
        },
        "eScan Antivirus (Linux)": {
            "status": 1,
            "results": r"EICAR-Test-File \(not a virus\)\(DB\)",
            "version": "7.0-18",
            "duration": MAXTIME_NORMAL_PROBE,
        },
        "ESET File Security (Linux)": {
            "status": 1,
            "results": "Eicar test file",
            "version": "4.0.82",
            "duration": MAXTIME_FAST_PROBE,
        },
        "F-PROT Antivirus (Linux)": {
            "status": 1,
            "results": r"EICAR_Test_File \(exact\)",
            "version": "4.6.5.141",
            "duration": MAXTIME_NORMAL_PROBE,
        },
        "FSecure Antivirus (Linux)": {
            "status": 1,
            "results": r"EICAR_Test_File \[FSE\]",
            "version": "11.00",
            "duration": MAXTIME_NORMAL_PROBE,
        },
        "GData Anti-Virus (Windows)": {
            "status": 1,
            "results": r"Virus: EICAR-Test-File \(not a virus\) \(Engine A\)",
            "version": "5.0.15051.292",
            "duration": MAXTIME_FAST_PROBE,
        },
        "Kaspersky Anti-Virus (Windows)": {
            "status": 1,
            "results": "EICAR-Test-File",
            "version": "16.0.0.694",
            "duration": MAXTIME_FAST_PROBE,
        },
        "McAfee VirusScan Command Line scanner (Linux)": {
            "status": 1,
            "results": "EICAR test file",
            "version": "6.0.4.564",
            "duration": MAXTIME_NORMAL_PROBE,
        },
        "McAfee VirusScan Command Line scanner (Windows)": {
            "status": 1,
            "results": "EICAR test file",
            "version": "6.0.4.564",
            "duration": MAXTIME_NORMAL_PROBE,
        },
        "McAfee VirusScan Daemon (Linux)": {
            "status": 1,
            "results": "EICAR test file",
            "version": "6.0.4.564",
            "duration": MAXTIME_FAST_PROBE,
        },
        "Sophos Anti-Virus (Linux)": {
            "status": 1,
            "results": "EICAR-AV-Test",
            "version": "5.21.0",
            "duration": MAXTIME_NORMAL_PROBE,
        },
        "Sophos Endpoint Protection (Windows)": {
            "status": 1,
            "results": "EICAR-AV-Test",
            "version": "10.6",
            "duration": MAXTIME_NORMAL_PROBE,
        },
        "Windefender Anti-Virus (Windows)": {
            "status": 1,
            "results": "Virus:DOS/EICAR_Test_File",
            "version": "4.10.14393.0",
            "duration": MAXTIME_FAST_PROBE,
        },
        "VirusBlokAda Console Scanner (Linux)": {
            "status": 1,
            "results": "EICAR-Test-File",
            "version": "3.12.26.4",
            "duration": MAXTIME_NORMAL_PROBE,
        },
        "Zoner Antivirus (Linux)": {
            "status": 1,
            "results": "EICAR.Test.File-NoVirus",
            "version": "1.3.0",
            "duration": MAXTIME_NORMAL_PROBE,
        },
    },
    "metadata": {
        "Dummy": {
            "status": 1,
            "results": EICAR_HASH,
            "version": None,
            "duration": MAXTIME_FAST_PROBE,
        },
        "LIEF": {
            "status": 1,
            "results": NOT_CHECKED,
            "version": "0.8.3-18d5b75",
            "duration": MAXTIME_FAST_PROBE,
        },
        "PEiD PE Packer Identifier": {
            "status": 0,
            "results": "Not a PE",
            "version": None,
            "duration": MAXTIME_FAST_PROBE,
        },
        "PE Static Analyzer": {
            "status": 0,
            "results": "Not a PE file",
            "version": None,
            "duration": MAXTIME_FAST_PROBE,
        },
        "TrID File Identifier": {
            "status": 1,
            "results": NOT_CHECKED,
            "version": None,
            "duration": MAXTIME_FAST_PROBE,
        },
    },
    "tools": {
        "Unarchive": {
            "status": -1,
            "results": None,
            "version": None,
            "duration": MAXTIME_FAST_PROBE,
        },
    },
    "external": {
        "VirusTotal": {
            "status": 1,
            "results": r"detected by \d{1,2}/\d{2}",
            "version": None,
            "duration": MAXTIME_FAST_PROBE,
        },
    },
}


##############################################################################
# Test Cases
##############################################################################
class EicarTestCase(asynctest.TestCase):

    async def setUp(self):
        async with AAPI() as api:
            self.probes = await api.probes.list()

    def _check_result(self, result, scanid, filelist, statuses,
                      range_finished, range_total):
        self.assertEqual(result.scan.id, scanid)
        self.assertTrue(result.name in filelist)
        self.assertIn(result.status, statuses)
        self.assertIsNotNone(result.id)
        self.assertIn(result.probes_total, range_total)
        self.assertIn(result.probes_finished, range_finished)

    def _check_results(self, results, scanid, filelist, statuses,
                       nb_finished, nb_total,
                       none_infos=False, none_results=False):
        self.assertCountEqual([r.name for r in results], filelist)
        for result in results:
            self._check_result(result, scanid, filelist, statuses,
                               nb_finished, nb_total)
            if none_infos is True:
                self.assertIsNone(result.file.md5)
            if none_results is True:
                self.assertIsNone(result.probe_results)
        return

    def _check_probe_result(self, probe_results, ref_results):
        for (pr_cat, pr_dict) in probe_results.items():
            for (probename, probe_result) in pr_dict.items():
                try:
                    ref_res = ref_results[pr_cat][probename]
                except KeyError:
                    self.assertFalse(True,
                                     "Missing probe %s ref_result" %
                                     probename)

                self.assertEqual(probe_result["status"],
                                 ref_res["status"],
                                 "%s status %s got %s" %
                                 (probename,
                                  ref_res["status"],
                                  probe_result["status"])
                                 )
                if probe_result["version"] != ref_res["version"]:
                    logging.warning("Outdated version of %s: latest %s got %s"
                                    % (probename,
                                       ref_res["version"],
                                       probe_result["version"])
                                    )
                if ref_res["results"] == NOT_CHECKED:
                    pass
                elif ref_res["results"] is not None:
                    self.assertIsNotNone(re.match(ref_res["results"],
                                                  probe_result["results"]),
                                         "%s results %s got %s" %
                                         (probename,
                                          ref_res["results"],
                                          probe_result["results"])
                                         )
                else:
                    self.assertIsNone(probe_result["results"],
                                      "%s results %s got %s" %
                                      (probename,
                                       ref_res["results"],
                                       probe_result["results"])
                                      )
                self.assertLessEqual(probe_result["duration"],
                                     ref_res["duration"],
                                     "%s duration %s got %s" %
                                     (probename,
                                      ref_res["duration"],
                                      probe_result["duration"])
                                     )
        return

    async def _test_scan_file(
            self, filelist, probelist, force=True, mimetype_filtering=None,
            resubmit_files=None, timeout=SCAN_TIMEOUT_SEC):
        nb_probes = len(probelist)
        nb_files = len(filelist)
        nb_jobs = nb_probes * nb_files
        filenames = [p.name for p in filelist]

        async with AAPI() as api:
            scan = await api.scans.scan(
                filelist, force=force, probes=probelist,
                mimetype_filtering=mimetype_filtering,
                resubmit_files=resubmit_files)

            start = time.time()
            while not scan.is_finished():
                self._check_results(
                        scan.files_ext, scan.id, filenames, [None, 0, 1],
                        range(nb_probes + 1), range(nb_jobs + 1), True, True)
                time.sleep(BEFORE_NEXT_PROGRESS)
                now = time.time()
                self.assertLessEqual(now, start + timeout, "Results Timeout")
                scan = await api.scans.get(scan)

            # Scan finished
            # if no probe has been run then status should be None
            statuses = [0, 1] if scan.probes_total > 0 else [None]
            self._check_results(
                    scan.files_ext, scan.id, filenames, statuses,
                    [scan.probes_total], [scan.probes_total], True, True)
            res = {}
            for result in scan.files_ext:
                file_result = await api.scans.result(result.id)
                # if no probe has been run then status should be None
                statuses = [-1, 0, 1] if file_result.probes_total else [None]
                self.assertIn(file_result.status, statuses)
                self.assertEqual(
                    file_result.probes_finished, file_result.probes_total)
                results_cnt = sum(
                        len(rs) for rs in file_result.probe_results.values())
                self.assertEqual(results_cnt, file_result.probes_total)
                res[result.name] = file_result.probe_results
            return res

    def assertListContains(self, list1, list2):
        for elt in list1:
            self.assertIn(elt, list2)


class IrmaEicarTest(EicarTestCase):

    async def _scan_eicar(self, probe):
        if probe not in self.probes:
            raise asynctest.SkipTest("Skipping %s not present" % probe)
        probelist = [probe]
        filelist = [EICAR_PATH]
        res = await self._test_scan_file(filelist, probelist, force=True)
        self._check_probe_result(res[EICAR_NAME], EICAR_RESULTS)

    async def test_scan_avg(self):
        await self._scan_eicar('AVGAntiVirusFree')

    async def test_scan_avast(self):
        await self._scan_eicar('AvastCoreSecurity')

    async def test_scan_avira(self):
        await self._scan_eicar('Avira')

    async def test_scan_bitdefender(self):
        await self._scan_eicar('BitdefenderForUnices')

    async def test_scan_clamav(self):
        await self._scan_eicar('ClamAV')

    async def test_scan_comodo(self):
        await self._scan_eicar('ComodoCAVL')

    async def test_scan_drweb(self):
        await self._scan_eicar('DrWeb')

    async def test_scan_dummy(self):
        await self._scan_eicar('Dummy')

    async def test_scan_emsisoft_windows(self):
        await self._scan_eicar('ASquaredCmdWin')

    async def test_scan_escan(self):
        await self._scan_eicar('EScan')

    async def test_scan_eset_file_security(self):
        await self._scan_eicar('EsetFileSecurity')

    async def test_scan_fprot(self):
        await self._scan_eicar('FProt')

    async def test_scan_fsecure(self):
        await self._scan_eicar('FSecure')

    async def test_scan_gdata_windows(self):
        await self._scan_eicar('GDataWin')

    async def test_scan_kaspersky_windows(self):
        await self._scan_eicar('KasperskyWin')

    async def test_scan_lief(self):
        await self._scan_eicar('LIEF')

    async def test_scan_mcafee(self):
        await self._scan_eicar('McAfeeVSCL')

    async def test_scan_mcafee_windows(self):
        await self._scan_eicar('McAfeeVSCLWin')

    async def test_scan_mcafeed(self):
        await self._scan_eicar('McAfee-Daemon')

    async def test_scan_peid(self):
        await self._scan_eicar('PEiD')

    async def test_scan_sophos(self):
        await self._scan_eicar('Sophos')

    async def test_scan_sophos_windows(self):
        await self._scan_eicar('SophosWin')

    async def test_scan_staticanalyzer(self):
        await self._scan_eicar('StaticAnalyzer')

    async def test_scan_trid(self):
        await self._scan_eicar('TrID')

    async def test_scan_virustotal(self):
        # dont raise on VT error cause of API limitations
        # to 4 requests per minute
        try:
            await self._scan_eicar('VirusTotal')
        except Exception:
            raise asynctest.SkipTest("Virustotal test Failed")

    async def test_scan_virusblokada(self):
        await self._scan_eicar('VirusBlokAda')

    async def test_scan_windefender(self):
        await self._scan_eicar('WinDefender')

    async def test_scan_zoner(self):
        await self._scan_eicar('Zoner')

    async def test_scan_all_probes(self):
        filelist = [EICAR_PATH]
        # remove Virustotal from grouped scan as public API is limited to 4
        # requests per minute
        probelist = [p for p in self.probes if p != 'VirusTotal']

        res = await self._test_scan_file(filelist, probelist, force=True)
        self._check_probe_result(res[EICAR_NAME], EICAR_RESULTS)


if __name__ == "__main__":
    asynctest.main()
