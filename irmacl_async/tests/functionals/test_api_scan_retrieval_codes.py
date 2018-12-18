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
import os
import hashlib
import tempfile
from irmacl_async import AAPI, IrmaError
import aiohttp
from pathlib import Path


cwd = os.path.dirname(__file__)
SAMPLES_DIR = Path(cwd) / "samples"
FILENAMES = ["fish", "eicar.com"]
FILEPATHS = list(SAMPLES_DIR / Path(x) for x in FILENAMES)
HASH = "7cddf3fa0f8563d49d0e272208290fe8fdc627e5cae0083d4b7ecf901b2ab6c8"


async def srcode_api_enabled():
    try:
        async with AAPI() as api:
            # Try to create a srcode with a wrong parameter
            # if srcode api is enabled it will respond 400 - bad request
            # else 404 not found
            await api.srcodes.new('')
    except aiohttp.ClientResponseError as e:
        if e.status == 400:
            return True
        elif e.status == 404:
            return False
        else:
            raise e


class IrmaAPISRCodesTests(asynctest.TestCase):

    async def setUp(self):
        self.api = await AAPI().__aenter__()
        self.probes = await self.api.probes.list()
        if not await srcode_api_enabled():
            raise asynctest.SkipTest(
                "Skipping srcode API disabled")

    async def tearDown(self):
        await self.api.__aexit__(None, None, None)

    async def test_srcode_new(self):
        fileslist = [FILEPATHS[0]]
        probes = [self.probes[0]]
        scan = await self.api.scans.scan(fileslist, force=False, probes=probes)
        res = await self.api.srcodes.new(scan)
        srcode = res.id
        self.assertEqual(len(srcode), 10)

    async def test_srcode_get(self):
        fileslist = [FILEPATHS[0]]
        probes = [self.probes[0]]
        scan = await self.api.scans.scan(fileslist, force=False, probes=probes)
        res = await self.api.srcodes.new(scan)
        srcode = res.id
        res = await self.api.srcodes.get(srcode)
        self.assertEqual(len(res.files_ext), len(fileslist))

    async def test_srcode_get_file(self):
        scan = await self.api.scans.scan(FILEPATHS, force=False,
                                         linger=True,
                                         probes=self.probes)
        res = await self.api.srcodes.new(scan)
        srcode = res.id
        res = await self.api.srcodes.get(srcode)
        results = res.files_ext
        print("Results: {}".format(results))
        for r in results:
            if r.name == "eicar.com":
                virus_file = r
            else:
                clean_file = r
        self.assertEqual(virus_file.status, 1)
        self.assertEqual(clean_file.status, 0)

    async def test_srcode_download_clean_file(self):
        scan = await self.api.scans.scan(
                FILEPATHS, force=False, linger=True, probes=self.probes)
        srcode = await self.api.srcodes.new(scan)
        qscan = await self.api.srcodes.get(srcode)
        for r in qscan.files_ext:
            if r.name == "fish":
                clean_file = r
        dst = tempfile.NamedTemporaryFile(delete=False)
        await self.api.srcodes.download_file(
                srcode,
                clean_file.id,
                Path(dst.name))
        h = hashlib.sha256()
        with Path(dst.name).open("rb") as f:
            h.update(f.read())
        os.unlink(dst.name)
        hashval = h.hexdigest()
        self.assertEqual(hashval, HASH)

    async def test_srcode_download_virus_file(self):
        scan = await self.api.scans.scan(FILEPATHS, force=False,
                                         linger=True,
                                         probes=self.probes)
        res = await self.api.srcodes.new(scan)
        srcode = res.id
        res = await self.api.srcodes.get(srcode)
        results = res.files_ext
        for r in results:
            if r.name == "eicar.com":
                virus_file = r
        dst = tempfile.NamedTemporaryFile(delete=False)
        with self.assertRaises(IrmaError):
            await self.api.srcodes.download_file(
                    srcode,
                    virus_file.id,
                    Path(dst.name))

    async def test_srcode_download_clean_file_wrong_srcode(self):
        scan = await self.api.scans.scan(FILEPATHS, force=False,
                                         linger=True,
                                         probes=self.probes)
        res = await self.api.srcodes.new(scan)
        srcode1 = res.id

        scan = await self.api.scans.scan(FILEPATHS, force=False,
                                         linger=True,
                                         probes=self.probes)
        res = await self.api.srcodes.new(scan)
        srcode2 = res.id
        res = await self.api.srcodes.get(srcode2)
        results = res.files_ext
        for r in results:
            if r.name == "fish":
                clean_file = r
        dst = tempfile.NamedTemporaryFile(delete=False)
        with self.assertRaises(IrmaError):
            await self.api.srcodes.download_file(
                    srcode1,
                    clean_file.id,
                    Path(dst.name))


if __name__ == "__main__":
    asynctest.main()
