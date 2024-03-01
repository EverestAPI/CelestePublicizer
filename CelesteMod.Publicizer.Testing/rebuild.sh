#!/usr/bin/env bash

rm ~/.nuget/packages/celestemod.publicizer
rm bin obj ../CelesteMod.Publicizer/bin ../CelesteMod.Publicizer/obj

dotnet build ../CelesteMod.Publicizer
dotnet restore
dotnet run -v n