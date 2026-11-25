# First original scene-to-pixel path

Four original dashboard scenes (two DVD splash layouts and two display settings images) have a consistent three-element DATA structure with XuiCanvas, XuiScene and XuiImage. Two observed property-record layouts differ by an optional pivot vector. The decoder accepts only these exact layouts, checks original STRN/typed tables and known header counts, and rejects other layouts rather than inventing element semantics. The position, scale and pivot interpretation is supported by the independently observed splash centers: the 4:3 and widescreen variants produce centered bounds after scaling about the optional pivot. It is a candidate original layout interpretation, not a complete recursive element grammar.

The native path consumes original scene data, resolves the actual texture from its own archive or the original shared resource mount, decodes PNG and rasterizes on a transparent RGBA8 canvas with pixel-center nearest sampling. The independent Python/Pillow oracle decodes the original textures and computes output pixels using the candidate transform. Four full canvas hashes are pinned in the original audit. Matching these proves the diagnostic implementation, not original Xbox GPU pixel parity; filtering, blending, color transforms, general UI layout, animation and navigation remain outstanding.

To generate local previews from your pinned originals (not distributed in the repository):

```sh
cmake -S . -B build/native -DCMAKE_BUILD_TYPE=Release
cmake --build build/native --parallel
python tools/fetch_originals.py --only dash_basic --only shared_resources
python tools/verify_image_scenes.py build/native/x360_image_scene_probe --preview-dir build/previews
```

The CI run verifies digests only and does not publish the original art or the rendered pixels. The diagnostic renderer is reusable with future scene grammar work; it is not a bootable dashboard.
