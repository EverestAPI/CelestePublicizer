# CelesteMod.Publiczer

This package automatically makes all private types/methods/fields from vanilla Celeste public.

Changes to the Celeste assembly, made by Everest are kept at their original visibility to avoid mods using Everest-internal APIs.

## Usage

Simply replace the `Celeste.dll` reference

```xml
<Reference Include="$(CelestePrefix)\Celeste.dll" Private="false" />
```

with this package:


```xml
<PackageReference Include="CelesteMod.Publicizer" Version="1.0.0" CelesteAssembly="$(CelestePrefix)\Celeste.dll" />
```

and everything should just work.

NOTE: You might need to invalidate the caches of your IDE, for it to properly work!
