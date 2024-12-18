# Pre-requisites

- IDA 9 Pro.
- Python 3.10 or newer with `pip`. Use `idapyswitch` (in your IDA installation
  folder) to configure which Python environment is used by IDA.
- Git (for installation).

# Quick installation and upgrade from IDA

Switch IDA console from **IDC** to **Python**, and run the following:

```python
import urllib.request; exec(urllib.request.urlopen("https://raw.githubusercontent.com/zenyard/decompai-ida-public/main/install_from_ida.py").read())
```

This will run a script performing the steps in next section.

# Manual installation

- Install package in same Python environment used by IDA:

  ```sh
  pip install git+https://github.com/zenyard/decompai-ida-public.git
  ```

  Use `idapyswitch` to verify or change the Python environment used by IDA.

- Add `decompai_stub.py` to [`$IDAUSR/plugins/`][1] folder (you may need to
  create this folder).

- Add the `decompai.json` to [`$IDAUSR/`][1] folder, and replace `<API KEY>`
  with your API key.

[1]:
  https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr
