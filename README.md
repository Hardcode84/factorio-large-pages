# Factorio `tbbmalloc` proxy injection with large/huge pages support

This hack is intended to replace default memory allocator with `tbbmalloc` and use large pages on windows.

## Enabling large pages support

To enable large pages for the current user, follow instructions from microsoft https://learn.microsoft.com/en-us/windows/win32/memory/large-page-support

Beware: large pages are non-pageable on windows, make sure you have enogh free RAM, otherwise your system may become unresponsive or just freeze completely (32Gb should be enough).

## TBB with large pages enabled

You need to compile a patched version of TBB from https://github.com/Hardcode84/oneTBB/tree/huge-pages-win

```
mkdir build
mkdir install
cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../install .
ninja install
```

## Building launcher and proxy

```
mkdir build
cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DTBB_DIR=<tbb-install>/lib/cmake/TBB .
ninja all
```

## Running proxy

**Only steam version is supported for now**

Copy `tbb12.dll`, `tbbmalloc.dll`, `tbbmalloc_proxy.dll` and `proxy.dll` to `***\steamapps\common\Factorio\bin\x64` dir.

Edit factorio launch options to `<path-to-launcher>/launcher.exe %command%`.
Any additional options will be passed directly to `factorio.exe`, e.g. to run bencmark:

`<path-to-launcher>/launcher.exe %command% --benchmark "<path-to-save>.zip" --benchmark-ticks 1000 --disable-audio`