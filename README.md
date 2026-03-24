# FLIR Batch Parameter Editor

Run:

```powershell
& 'C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe' 'C:\Users\User\Desktop\OUTPUT\FLIRTOOL\flir_batch_editor.py'
```

What it does:

- Lets you choose a folder or multiple JPEG files.
- Batch edits these FLIR CameraInfo values inside radiometric JPEGs:
  emissivity, reflected temperature, distance, atmospheric temperature,
  external optics temperature, external optics transmission, and relative humidity.
- Can create a `.bak` backup before each write.
- Includes an `Inspect Selected Files` action so you can confirm a file is patchable first.

Important:

- This targets FLIR radiometric JPEG files with an embedded FLIR `CameraInfo` record.
- Unsupported files are skipped and listed in the log.
