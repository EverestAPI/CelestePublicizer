using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace CelestePublicizer;

public class PublicizeTask : Task {
    [Required]
    public string IntermediateOutputPath { get; set; }

    [Required]
    public ITaskItem[] ReferencePath { get; set; }
    
    [Required]
    public ITaskItem[] PackageReference { get; set; }

    public override bool Execute()
    {
        Console.WriteLine("hi");
        foreach (var taskItem in PackageReference)
        {
            Console.WriteLine(taskItem);
        }
        
        return true;
    }
    
    // Adapted from https://github.com/BepInEx/BepInEx.AssemblyPublicizer/blob/master/BepInEx.AssemblyPublicizer.MSBuild/PublicizeTask.cs#L132-L168
    private static string ComputeHash(byte[] bytes, string mask) {
        static void Hash(ICryptoTransform hash, byte[] buffer) {
            hash.TransformBlock(buffer, 0, buffer.Length, buffer, 0);
        }

        static void HashString(ICryptoTransform hash, string str) => Hash(hash, Encoding.UTF8.GetBytes(str));
        static void HashBool(ICryptoTransform hash, bool value) => Hash(hash, BitConverter.GetBytes(value));
        static void HashInt(ICryptoTransform hash, int value) => Hash(hash, BitConverter.GetBytes(value));

        using var md5 = MD5.Create();

        HashString(md5, typeof(PublicizeTask).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>().InformationalVersion);
        HashString(md5, mask);

        md5.TransformFinalBlock(bytes, 0, bytes.Length);

        return ByteArrayToString(md5.Hash);
    }
    
    private static string ByteArrayToString(IReadOnlyCollection<byte> data) {
        var builder = new StringBuilder(data.Count * 2);

        foreach (var b in data) {
            builder.AppendFormat("{0:x2}", b);
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