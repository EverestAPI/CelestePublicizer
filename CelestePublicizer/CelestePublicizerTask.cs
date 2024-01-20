using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.IO;
using BepInEx.AssemblyPublicizer;
using FieldAttributes = AsmResolver.PE.DotNet.Metadata.Tables.Rows.FieldAttributes;
using MethodAttributes = AsmResolver.PE.DotNet.Metadata.Tables.Rows.MethodAttributes;
using TypeAttributes = AsmResolver.PE.DotNet.Metadata.Tables.Rows.TypeAttributes;

namespace CelestePublicizer;

public class PublicizeTask : Task {

    [Required]
    public string IntermediateOutputPath { get; set; }
    
    [Required]
    public ITaskItem[] PackageReference { get; set; }
    
    [Output]
    public ITaskItem PublicizedReference { get; private set; }

    public override bool Execute() {
        const string PackageName = "CelestePublicizer";
        var celestePackages = PackageReference
            .Where(item => item.TryGetMetadata("Identity", out string identity) && identity == PackageName)
            .ToArray();

        if (celestePackages.Length == 0) return true;
        if (celestePackages.Length > 1) {
            Log.LogError($"Specified {PackageName} package more than once");
            return false;
        }
        
        var celestePackage = celestePackages[0];
        if (!celestePackage.TryGetMetadata("CelesteAssembly", out string celesteAssemblyPath)) {
            Log.LogError($"The \"CelesteAssembly\" property needs to be specified for the {PackageName} package");
            return false;
        }
        
        string outputAssemblyPath = $"{IntermediateOutputPath}Celeste-publicized.dll";
        string outputHashPath = $"{outputAssemblyPath}.md5";
        
        var taskAssembly = typeof(PublicizeTask).Assembly;
        
        var celesteAssemblyBytes = File.ReadAllBytes(celesteAssemblyPath);
        var celesteAssembly = AssemblyDefinition.FromBytes(celesteAssemblyBytes);
        
        var origAssemblyStream = taskAssembly.GetManifestResourceStream($"{PackageName}.Assets.Celeste.exe")!;
        var memoryStream = new MemoryStream(); 
        origAssemblyStream.CopyTo(memoryStream);
        var origAssemblyBytes = memoryStream.ToArray();
        var origAssembly = AssemblyDefinition.FromBytes(origAssemblyBytes);

        var hash = ComputeHash(celesteAssemblyBytes, origAssemblyBytes);
        if (File.Exists(outputHashPath) && File.ReadAllText(outputHashPath) == hash) {
            Log.LogMessage($"{celesteAssemblyPath} was already publicized, skipping");
            // return true;
        }
        
        PublicizeAssembly(celesteAssembly, origAssembly);
        
        var module = celesteAssembly.ManifestModule;
        module.FatalWrite(outputAssemblyPath);

        PublicizedReference = new TaskItem(outputAssemblyPath);
        celestePackage.CopyMetadataTo(PublicizedReference);
        celestePackage.RemoveMetadata("ReferenceAssembly");
        
        var originalDocumentationPath = Path.ChangeExtension(celesteAssemblyPath, "xml");
        if (File.Exists(originalDocumentationPath)) {
            File.Copy(originalDocumentationPath, Path.ChangeExtension(outputAssemblyPath, "xml"), true);
        }
        
        File.WriteAllText(outputHashPath, hash);
        Log.LogMessage($"Publicized {celesteAssemblyPath}");
        
        return true;
    }
    
    // Adapted from https://github.com/psyGamer/BepInEx.AssemblyPublicizer/blob/master/BepInEx.AssemblyPublicizer/AssemblyPublicizer.cs
    private static void PublicizeAssembly(AssemblyDefinition assembly, AssemblyDefinition maskAssembly)
    {
        var module = assembly.ManifestModule!;
        var maskModule = maskAssembly.ManifestModule!;

        var maskTypes = maskModule.GetAllTypes().ToDictionary(x => x.FullName);
        
        foreach (var typeDefinition in module.GetAllTypes()) {
            if (!maskTypes.ContainsKey(typeDefinition.FullName))
                continue;

            PublicizeType(typeDefinition, maskTypes[typeDefinition.FullName]);
        }
    }
    
    private static void PublicizeType(TypeDefinition typeDefinition, TypeDefinition maskTypeDefinition) {
        if (!typeDefinition.IsNested && !typeDefinition.IsPublic || typeDefinition.IsNested && !typeDefinition.IsNestedPublic) {
            typeDefinition.Attributes &= ~TypeAttributes.VisibilityMask;
            typeDefinition.Attributes |= typeDefinition.IsNested ? TypeAttributes.NestedPublic : TypeAttributes.Public;
        }

        var maskMethods = maskTypeDefinition?.Methods.Select(x => x.FullName).ToArray();
        foreach (var methodDefinition in typeDefinition.Methods) {
            if (maskMethods != null && !maskMethods.Contains(methodDefinition.FullName))
                continue;
            PublicizeMethod(methodDefinition);
        }

        foreach (var propertyDefinition in typeDefinition.Properties)
        {
            if (propertyDefinition.GetMethod is { } getMethod) PublicizeMethod(getMethod, ignoreCompilerGeneratedCheck: true);
            if (propertyDefinition.SetMethod is { } setMethod) PublicizeMethod(setMethod, ignoreCompilerGeneratedCheck: true);
        }

        var maskFields = maskTypeDefinition?.Fields.Select(x => x.FullName).ToArray();
        
        var eventNames = new HashSet<Utf8String?>(typeDefinition.Events.Select(e => e.Name));
        foreach (var fieldDefinition in typeDefinition.Fields)
        {
            if (fieldDefinition.IsPrivateScope)
                continue;
            if (maskFields != null && !maskFields.Contains(fieldDefinition.FullName))
                continue;

            if (!fieldDefinition.IsPublic)
            {
                // Skip event backing fields
                if (eventNames.Contains(fieldDefinition.Name))
                    continue;
                if (fieldDefinition.IsCompilerGenerated())
                    continue;

                fieldDefinition.Attributes &= ~FieldAttributes.FieldAccessMask;
                fieldDefinition.Attributes |= FieldAttributes.Public;
            }
        }
    }
    
    private static void PublicizeMethod(MethodDefinition methodDefinition, bool ignoreCompilerGeneratedCheck = false) {
        if (methodDefinition.IsCompilerControlled)
            return;
        if (!ignoreCompilerGeneratedCheck && methodDefinition.IsCompilerGenerated())
            return;

        if (!methodDefinition.IsPublic) {
            methodDefinition.Attributes &= ~MethodAttributes.MemberAccessMask;
            methodDefinition.Attributes |= MethodAttributes.Public;
        }
    }
    
    // Adapted from https://github.com/BepInEx/BepInEx.AssemblyPublicizer/blob/master/BepInEx.AssemblyPublicizer.MSBuild/PublicizeTask.cs#L132-L168
    private static string ComputeHash(byte[] bytes, byte[] maskBytes) {
        static void Hash(ICryptoTransform hash, byte[] buffer) {
            hash.TransformBlock(buffer, 0, buffer.Length, buffer, 0);
        }

        static void HashString(ICryptoTransform hash, string str) => Hash(hash, Encoding.UTF8.GetBytes(str));

        using var md5 = MD5.Create();

        HashString(md5, typeof(PublicizeTask).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion);
        Hash(md5, maskBytes);

        md5.TransformFinalBlock(bytes, 0, bytes.Length);

        return ByteArrayToString(md5.Hash);
    }
    
    private static string ByteArrayToString(IReadOnlyCollection<byte> data) {
        var builder = new StringBuilder(data.Count * 2);
        foreach (var b in data) {
            builder.Append($"{b:x2}");
        }
        return builder.ToString();
    }
}

// Taken from https://github.com/BepInEx/BepInEx.AssemblyPublicizer/blob/master/BepInEx.AssemblyPublicizer.MSBuild/Extensions.cs
internal static class Extensions {
    public static bool HasMetadata(this ITaskItem taskItem, string metadataName) {
        var metadataNames = (ICollection<string>)taskItem.MetadataNames;
        return metadataNames.Contains(metadataName);
    }

    public static bool TryGetMetadata(this ITaskItem taskItem, string metadataName, [NotNullWhen(true)] out string metadata) {
        if (taskItem.HasMetadata(metadataName)) {
            metadata = taskItem.GetMetadata(metadataName);
            return true;
        }

        metadata = null;
        return false;
    }
}