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

import asyncio
import asynctest
import re
import tempfile
import hashlib
from irmacl_async.apiclient import AAPI, IrmaError
from pathlib import Path


SAMPLES_DIR = Path(__file__).parent / "samples"
FILENAMES = ["fish", "ls"]
HASHES = ["7cddf3fa0f8563d49d0e272208290fe8fdc627e5cae0083d4b7ecf901b2ab6c8",
          "71f30d658966bcc7ea162b4e0f20d2305d4a003e854305b524280f4c2a3b48a3",
          "3826e18a5dc849670744752fd27c4eec6136ac90",
          "8d50d7a3929a356542119aa858c492442655e097",
          "07edba6f3f181bad9a56a87d4039487a",
          "e718241e1cc6472d4f4bac20c59a0179"]
FILEPATHS = [SAMPLES_DIR / fn for fn in FILENAMES]


class IrmaAPITests(asynctest.TestCase):

    async def setUp(self):
        self.api = await AAPI().__aenter__()
        self.probes = await self.api.probes.list()

    async def tearDown(self):
        await self.api.__aexit__(None, None, None)

    def _validate_uuid(self, uuid):
        regex = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',
                           re.IGNORECASE)
        return regex.match(uuid) is not None

    def _check_scan(self, scan, scanid, range_status, filelist,
                    range_finished, range_total,
                    force, mimetype_filtering, resubmit_files):
        nb_files = len(filelist)
        self.assertEqual(scan.id, scanid)
        self.assertIn(scan.pstatus, range_status)
        self.assertEqual(type(scan.files_ext), list)
        self.assertEqual(len(scan.files_ext), nb_files)
        self.assertIn(scan.probes_finished, range_finished)
        self.assertIn(scan.probes_total, range_total)
        self.assertEqual(scan.force, force)
        self.assertEqual(scan.mimetype_filtering, mimetype_filtering)
        self.assertEqual(scan.resubmit_files, resubmit_files)

    async def test_about(self):
        res = await self.api.about()
        self.assertIn("version", res)


class IrmaAPIScanTests(IrmaAPITests):

    async def test_probe_list(self):
        self.assertTrue(type(self.probes), list)
        self.assertNotEqual(len(self.probes), 0)

    async def test_files_upload(self):
        fw = await self.api.files.upload(FILEPATHS[0])
        self.assertEqual(fw.name, FILENAMES[0])
        self.assertIsNone(fw.scan)

    async def test_files_new(self):
        fpath = FILEPATHS[0]
        fw = await self.api.files.new(fpath.read_bytes(), fpath.name)
        self.assertEqual(fw.name, fpath.name)
        self.assertIsNone(fw.scan)

    async def test_scan_launch(self):
        nb_jobs = len(FILENAMES) * len(self.probes)
        scan = await self.api.scans.scan(
                FILEPATHS, linger=True)
        self._check_scan(
            scan, scan.id, ["finished"], FILENAMES, range(nb_jobs+1),
            range(nb_jobs+1), True, True, True)

    async def test_scan_force(self):
        fileslist = [FILEPATHS[0]]
        probes = [self.probes[0]]
        nb_jobs = len(fileslist) * len(probes)
        scan = await self.api.scans.scan(fileslist, force=False, probes=probes)
        self._check_scan(scan, scan.id, ["ready", "uploaded",
                                         "launched", "finished"],
                         fileslist, range(nb_jobs + 1), range(nb_jobs + 1),
                         False, True, True)
        try:
            await self.api.scans.cancel(scan)
        except IrmaError:
            # could happen if scan is already finished
            pass

    async def test_mimetype_filtering(self):
        nb_jobs = len(FILEPATHS) * len(self.probes)
        scan = await self.api.scans.scan(
                FILEPATHS, mimetype_filtering=False)
        self._check_scan(scan, scan.id, ["ready", "uploaded",
                                         "launched", "finished"],
                         FILENAMES, range(nb_jobs + 1), range(nb_jobs + 1),
                         True, False, True)

        try:
            scan = await self.api.scans.cancel(scan)
            self._check_scan(scan, scan.id, ["cancelled"],
                             FILENAMES, range(nb_jobs + 1), range(nb_jobs + 1),
                             True, False, True)
        except IrmaError:
            self._check_scan(scan, scan.id, ["finished"],
                             FILENAMES, [nb_jobs], [nb_jobs],
                             True, False, True)

    async def test_resubmit_files(self):
            nb_jobs = len(FILEPATHS) * len(self.probes)
            scan = await self.api.scans.scan(
                    FILEPATHS, resubmit_files=False)
            self._check_scan(scan, scan.id, ["ready", "uploaded",
                                             "launched", "finished"],
                             FILENAMES, range(nb_jobs + 1), range(nb_jobs + 1),
                             True, True, False)
            try:
                scan = await self.api.scans.cancel(scan)
                self._check_scan(
                    scan, scan.id, ["cancelled"], FILENAMES,
                    range(nb_jobs + 1), range(nb_jobs + 1), True, True, False)
            except IrmaError:
                self._check_scan(
                    scan, scan.id, ["finished"], FILENAMES, [nb_jobs],
                    [nb_jobs], True, True, False)

    async def test_scan_files(self):
        nb_jobs = len(FILENAMES) * len(self.probes)
        fes = await asyncio.gather(
            *[self.api.files.upload(fp) for fp in FILEPATHS])
        scan = await self.api.scans.launch(fes)
        self._check_scan(scan, scan.id, ["ready", "uploaded",
                                         "launched", "finished"],
                         FILENAMES, range(nb_jobs + 1), range(nb_jobs + 1),
                         True, True, True)
        try:
            scan = await self.api.scans.cancel(scan)
            self._check_scan(scan, scan.id, ["cancelled"],
                             FILENAMES, range(nb_jobs + 1), range(nb_jobs + 1),
                             True, True, True)
        except IrmaError:
            self._check_scan(scan, scan.id, ["finished"],
                             FILENAMES, [nb_jobs], [nb_jobs],
                             True, True, True)

    async def test_scan_quick(self):
        # /scan/quick don't care about force and probes
        probes = self.probes[:1]
        nb_jobs = len(self.probes)
        scan = await self.api.scans.scan(
            FILEPATHS[0], force=False, probes=probes)
        self._check_scan(scan, scan.id, ["ready", "uploaded",
                                         "launched", "finished"],
                         [FILENAMES[0]], range(nb_jobs + 1),
                         range(nb_jobs + 1), True, True, True)
        try:
            scan = await self.api.scans.cancel(scan)
            self._check_scan(scan, scan.id, ["cancelled"],
                             [FILENAMES[0]], range(nb_jobs + 1),
                             range(nb_jobs + 1), True, True, True)
        except IrmaError:
            self._check_scan(scan, scan.id, ["finished"],
                             [FILENAMES[0]], [nb_jobs], [nb_jobs],
                             True, True, True)

    async def test_scan_get(self):
        scan = await self.api.scans.scan(FILEPATHS, linger=True)
        self._check_scan(scan, scan.id, ["finished"],
                         FILENAMES, [scan.probes_total], [scan.probes_total],
                         True, True, True)

    async def test_file_results_formatted(self):
        scan = await self.api.scans.scan(
                FILEPATHS, linger=True, mimetype_filtering=False)

        for result in scan.files_ext:
            self.assertTrue(self._validate_uuid(result.id))
            res = await self.api.scans.result(result.id)
            self.assertIn(res.name, FILENAMES)
            self.assertTrue(type(res.probe_results), dict)
            results_cnt = sum(len(rs) for rs in res.probe_results.values())
            self.assertEqual(results_cnt, res.probes_finished)

    async def test_file_results_not_formatted(self):
        scan = await self.api.scans.scan(
                FILEPATHS, linger=True, mimetype_filtering=False)

        for result in scan.files_ext:
            self.assertTrue(self._validate_uuid(result.id))
            res = await self.api.scans.result(result.id, full=True)
            self.assertIn(res.name, FILENAMES)
            self.assertEqual(type(res.probe_results), dict)
            results_cnt = sum(len(rs) for rs in res.probe_results.values())
            self.assertEqual(results_cnt, res.probes_finished)

    async def test_scan_empty_data(self):
        nb_jobs = len(self.probes)
        filename = "empty_file"
        fe = await self.api.files.new("", filename)
        scan = await self.api.scans.launch([fe])
        self._check_scan(scan, scan.id, ["ready", "uploaded",
                                         "launched", "finished"],
                         [filename], range(nb_jobs + 1),
                         range(nb_jobs + 1), True, True, True)
        try:
            scan = await self.api.scans.cancel(scan)
            self._check_scan(scan, scan.id, ["cancelled"],
                             [filename], range(nb_jobs + 1),
                             range(nb_jobs + 1), True, True, True)
        except IrmaError:
            self._check_scan(scan, scan.id, ["finished"],
                             [filename], [nb_jobs], [nb_jobs],
                             True, True, True)

    async def test_scan_empty_file(self):
        nb_jobs = len(self.probes)
        filename = "empty_file"
        filepath = SAMPLES_DIR / filename

        scan = await self.api.scans.scan([filepath])
        self._check_scan(scan, scan.id, ["ready", "uploaded",
                                         "launched", "finished"],
                         [filename], range(nb_jobs + 1),
                         range(nb_jobs + 1), True, True, True)
        try:
            scan = await self.api.scans.cancel(scan)
            self._check_scan(scan, scan.id, ["cancelled"],
                             [filename], range(nb_jobs + 1),
                             range(nb_jobs + 1), True, True, True)
        except IrmaError:
            self._check_scan(scan, scan.id, ["finished"],
                             [filename], [nb_jobs], [nb_jobs],
                             True, True, True)


class IrmaAPIFileTests(IrmaAPITests):

    async def test_file_search_name(self):
        await self.api.scans.scan(FILEPATHS, linger=True, force=False)
        for name in FILENAMES:
            page = await self.api.files.search({"name": name}, limit=1)
            total, res = page["total"], page["items"]
            self.assertEqual(type(res), list)
            self.assertEqual(len(res), 1)
            self.assertEqual(type(total), int)

    async def test_file_search_limit(self):
        page = await self.api.files.list()
        total = page["total"]
        if total > 10:
            offset = total - 10
            limit = 10
        else:
            offset = 0
            limit = total
        page = await self.api.files.list(offset=offset, limit=limit)
        res = page["items"]
        self.assertEqual(type(res), list)
        self.assertEqual(len(res), limit)

    async def test_file_search_hash(self):
        await self.api.scans.scan(FILEPATHS, linger=True, force=False)
        for hash in HASHES:
            page = await self.api.files.search({'hash': hash})
            res = page["items"]
            self.assertTrue(len(res) > 0)

    async def test_file_search_hash_name(self):
        with self.assertRaises(IrmaError):
            await self.api.files.search({"name": "name", "hash": "hash"})

    async def test_file_download(self):
        await self.api.scans.scan([FILEPATHS[0]], linger=True, force=False)
        with tempfile.NamedTemporaryFile() as dst:
            dstpath = Path(dst.name)
            await self.api.files.download(HASHES[0], dstpath)
            digest = hashlib.sha256(dstpath.read_bytes()).hexdigest()
            self.assertEqual(digest, HASHES[0])


class IrmaAPITagTests(IrmaAPITests):
    taglist = None
    file_sha256 = HASHES[0]
    file_path = FILEPATHS[0]
    file_name = FILENAMES[0]
    result = None
    former_tag = []

    async def setUp(self):
        async with AAPI() as api:
            if self.taglist is None:
                self.taglist = await api.tags.list()
            if not self.taglist:
                raise asynctest.SkipTest(
                    "Skipping No tag found (please add some)")
            # Insure file is present (Force=False)
            scan = await api.scans.scan(
                    [self.file_path], linger=True, force=False)
            self.result = await api.scans.result(scan.files_ext[0])
            # Insure file got no tags for test
            self.former_tags = self.result.file_infos.tags
            if self.former_tags:
                removals = [api.files.remove_tag(self.file_sha256, tag)
                            for tag in self.former_tags]
                await asyncio.gather(*removals)
                self.result = await api.scans.result(scan.files_ext[0])

    async def tearDown(self):
        async with AAPI() as api:
            # Restore tags
            self.result = await api.scans.result(self.result.id)
            self.assertEqual(self.file_sha256, self.result.file_sha256)
            self.assertEqual(self.file_sha256, self.result.file_infos.sha256)
            await asyncio.gather(*[api.files.remove_tag(self.file_sha256, tag)
                                   for tag in self.result.file_infos.tags])
            await asyncio.gather(*[api.files.remove_tag(self.file_sha256, tag)
                                   for tag in self.former_tags])

    async def test_about(self):
        pass

    async def test_tag_list(self):
        async with AAPI() as api:
            self.assertEqual(len(await api.tags.list()), len(self.taglist))

    async def test_file_tag_add_remove(self):
        async with AAPI() as api:
            for tag in self.taglist:
                await api.files.add_tag(self.file_sha256, tag)
                result = await api.scans.result(self.result)
                self.assertIn(tag, result.file_infos.tags)
            for tag in self.taglist:
                await api.files.remove_tag(self.file_sha256, tag)
                result = await api.scans.result(self.result)
                self.assertNotIn(tag, result.file_infos.tags)

    async def test_file_search_tag(self):
        async with AAPI() as api:
            self.assertEqual(len(self.result.file_infos.tags), 0)
            tagged = []
            for tag in self.taglist:
                await api.files.add_tag(self.file_sha256, tag)
                tagged.append(tag.id)
                page = await api.files.search(
                        {"name": self.file_name, "tags": tagged})
                self.assertGreater(page["total"], 0)
                self.assertIn(self.file_name, [x.name for x in page["items"]])

    async def test_file_search_not_existing_tag(self):
        invalid_tagid = max(x.id for x in self.taglist) + 1
        async with AAPI() as api:
            with self.assertRaises(IrmaError):
                await api.files.search({'tags': invalid_tagid})

    async def test_file_search_not_existing_tag_and_name(self):
        invalid_tagid = max(x.id for x in self.taglist) + 1
        async with AAPI() as api:
            with self.assertRaises(IrmaError):
                await api.files.search(
                    {"name": self.file_name, 'tags': invalid_tagid})

    async def test_file_tag_twice(self):
        async with AAPI() as api:
            page = await api.files.search({'hash': self.file_sha256})
            self.assertNotEqual(page["total"], 0)
            await api.files.add_tag(self.file_sha256, self.taglist[0])
            page = await api.files.search({"hash": self.file_sha256})
            self.assertGreaterEqual(page["total"], 1)
            with self.assertRaises(IrmaError):
                await api.files.add_tag(self.file_sha256, self.taglist[0])


if __name__ == "__main__":
    asynctest.main()
