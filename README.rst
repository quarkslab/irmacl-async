Irmacl-async: Asynchronous client library for IRMA API
======================================================

|docs|

IRMA is an asynchronous and customizable analysis system for suspicious files.
This repository is a subproject of IRMA and contains the source code for IRMA
API client.

Irmacl-async requires python 3.5+ and an IRMA server with **API version 2**. The
exact expected version is defined in ``AAPI.IRMA_VERSION``.

Installation
------------

From the sources, clone the repository and run

.. code-block:: console

   $ python setup.py install

Or with pip just run

.. code-block:: console

  $ pip install irmacl-async


Configuration
`````````````

Irmacl-async configuration is done with a ``Config`` object that should be
given to ``AAPI`` at initialisation. The details of expected configuration is
available with ``help(Config)``. A ``Config`` object can be initialized from an
irma.yml file, which is a yaml file containing the parameters of a ``Config``
object.  All parameters are optional.

.. code-block:: yaml

   api_endpoint: "https://172.16.1.30/api/v2"
   verify: true
   ca: /etc/irma/ca.crt
   cert: /etc/irma/client.crt
   key: /etc/irma/client.key
   submitter: kiosk
   submitter_id: kiosk-D205

irma.yml is searched in these locations in following order:

* current directory
* environment variable *IRMA_CONF*
* user home directory
* global directory  */etc/irma*

Once you set up a working irma.yml settings file, you could run tests on your
running IRMA server:

.. code-block:: console

   $ python setup.py test


Usage
-----

Irmacl-async is an asynchronous library. It is meant to ease the development of
python code that communicates with an IRMA server.

Hello world
```````````

.. code-block:: pycon

   >>> import asyncio
   >>> from irmacl_async import AAPI
   >>>
   >>> async def main():
   ...     async with AAPI() as api:
   ...         resp = await api.about()
   ...         print(resp['version'])
   ...
   >>> loop = asyncio.get_event_loop()
   >>> loop.run_until_complete(main())
   v2.2.3-20-g06a29b45

The ``main`` coroutine just prints the version of the IRMA server counterpart.
There is few things to notice in this example.

First, an async context pattern must be opened to create a session and perform
requests. Moreover, AAPI will check the version of IRMA and prints a warning if
it mismatches the expected one (``apicheck=False`` to prevent this behavior).
Irmacl-async uses ``aiohttp.ClientSession`` in backend, you can set
``AAPI().session`` manually at your own risks but it is not recommenced.

Second, ``api.about`` does not return a result but a ``Future`` that needs to
be awaited before being able to get its result.

Finally, the ``main`` coroutine cannot just be called as a regular function but
needs to be awaited from another coroutine or run into an event loop.


Basic usage
```````````

.. code-block:: pycon

   >>> import asyncio
   >>> from pathlib import Path
   >>> from irmacl_async import AAPI
   >>>
   >>> async def scandir(directory):
   ...     files = (p for p in directory.iterdir() if p.is_file())
   ...     async with AAPI() as api:
   ...         scan = await api.scans.scan(files, linger=True)
   ...         res = [api.scans.result(fe) for fe in scan.results]
   ...         return await asyncio.gather(*res)
   ...
   >>> loop = asyncio.get_event_loop()
   >>> d = Path("irmacl_async/tests/functionals/samples")
   >>> loop.run_until_complete(scandir(d))
   [FileExt.d13ab478-b24e-43a2-a51a-38c10355e929, ...]

The ``scandir`` coroutine is a bit more complex and benefits from the
asynchronicity of the irmacl-async library. It scans the contents of a directory and
wait for the result (``linger=True``). Then, it queries the result of every
individual file of the scan. Instead of a ``for`` loop, that would query the
files one at a time, it uses ``asyncio.gather``.  Finally it waits for every
request to be complete and returns the results.


References
----------

AAPI
````

Every method is -or at least should be- fully documented, use ``help(AAPI)`` or
``help(AAPI().files)`` to get a exhaustive list of every available method and
their parameters.

Objects
```````
::

   | Links between objects, example
   |                             +---------------+         +---------------+
   |                             |               |         |               |
   |   +---------------+    +----+ FileExt 0933  +---------+   File 3099   |
   |   |               |    |    |               |         |               |
   |   |   Scan 1de3   +----+    ----------------+         +---------------+
   |   |               |    |
   |   +----------------    |
   |                        |    +---------------+
   |                        |    |               |
   |                        +----+ FileExt aa1a  +----+
   |                             |               |    |    +---------------+
   |                             +---------------+    |    |               |
   |                                                  +----+   File ab89   |
   |   +---------------+                              |    |               |
   |   |               |         +---------------+    |    +---------------+
   |   |   Scan b987   +----+    |               |    |
   |   |               |    +----+ FileExt f823  +----+
   |   +---------------+         |               |
   |                             +---------------+

A ``File`` contains the actual contents of a file. Putting a file onto analysis
creates a ``FileExt`` that contains the results of the analysis for this file.
Finally a ``Scan`` is a collection of ``FileExts`` In the example above, the
scan b987 contains one file ab89. The scan 1de3 contains two files 3099 and
ab89.


IrmaFileInfo
  IrmaFileInfo are the metadata information linked to a IrmaFile

IrmaScan
  IrmaScan keep tracks of the IrmaFileExt scanned together, probe list used and
  scan options.

IrmaFileExt
  IrmaFileExt object are scan results for a IrmaFile. One IrmaFileExt could be
  linked to only one IrmaScan.  If you submit multiple times the same file and
  scan it each time, you create only one IrmaFile but create multiple
  IrmaFileExt all linked to the same IrmaFile.

IrmaTag
  Tag will be directly linked to IrmaFiles, each IrmaFileExt linked to this
  IrmaFile will be tagged indirectly.


Other
-----

Documentation
`````````````

The full IRMA documentation is available `on Read The Docs Website`_.


Getting help
````````````

Join the #qb_irma channel on irc.freenode.net. Lots of helpful people hang out
there.


Contribute to IRMA
``````````````````

IRMA is an ambitious project. Make yourself known on the #qb_irma channel on
irc.freenode.net. We will be please to greet you and to find a way to get you
involved in the project.


.. |docs| image:: https://readthedocs.org/projects/irma/badge/
    :alt: Documentation Status
    :scale: 100%
    :target: https://irma.readthedocs.io
.. _on Read The Docs Website: https://irma.readthedocs.io
