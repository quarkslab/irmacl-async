# -*- coding: utf-8 -*-

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
from pathlib import Path

from irmacl_async.apiclient import AAPI


SAMPLES_DIR = Path(__file__).parent / "samples"
ZIP_SAMPLE = "eicar.zip"
UTF8_SAMPLES = [
    "☀.vir", "فایل.exe", "вирус.exe", "ვირუსი.exe", "परीक्षण.exe", "病毒.exe"]
UTF8_PATHS = [SAMPLES_DIR / fname for fname in UTF8_SAMPLES]


class TestCornerCase(asynctest.TestCase):

    async def test_utf8(self):
        async with AAPI() as api:
            scan = await api.scans.scan(UTF8_PATHS, linger=True, force=False)

            results = [api.scans.result(res.id) for res in scan.files_ext]
            results = await asyncio.gather(*results)
            filenames = [res.name for res in results]
            self.assertCountEqual(filenames, UTF8_SAMPLES)

            async def assert_searchname(filename):
                res = await api.files.search({"name": filename}, limit=1)
                res = res["items"]
                self.assertEqual(len(res), 1)
                self.assertEqual(res[0].name, filename)

            asserts = [assert_searchname(filename)
                       for filename in UTF8_SAMPLES]
            await asyncio.gather(*asserts)

    async def test_zip(self):
        async with AAPI() as api:
            probelist = await api.probes.list()
            probe = 'Unarchive'
            if probe not in probelist:
                raise asynctest.SkipTest(
                        "Skipping {} not present" .format(probe))

            sample = SAMPLES_DIR / ZIP_SAMPLE
            scan = await api.scans.scan(
                [sample], raw=True, linger=True, probes=[probe], force=True)
            self.assertEqual(len(scan.files_ext), 2)
            self.assertEqual(scan.probes_finished, 1)


if __name__ == "__main__":
    asynctest.main()
