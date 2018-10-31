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
from pathlib import Path

from irmacl_async.apiclient import AAPI


SAMPLES_DIR = Path(__file__).parent / "samples"
ZIP_SAMPLE = "zipbomb.zip"


class TestZipBomb(asynctest.TestCase):

    async def test_zipbomb(self):
        async with AAPI() as api:
            probelist = await api.probes.list()
            probe = 'Unarchive'
            if probe not in probelist:
                raise asynctest.SkipTest(
                    "Skipping {} not present".format(probe))

            sample = SAMPLES_DIR / ZIP_SAMPLE
            scan = api.scans.scan(
                [sample], linger=True, probes=[probe], force=True)

            self.assertEqual(len(scan.results), 1)
            self.assertEqual(scan.probes_finished, 1)

            result = await api.scans.result(scan.results[0])

            self.assertEqual(len(result.probe_results), 1)
            probe_result = result.probe_results[0]
            self.assertEqual(probe_result.status, -1)
            self.assertIsNotNone(probe_result.error)
            self.assertNone(probe_result.results)


if __name__ == "__main__":
    asynctest.main()
