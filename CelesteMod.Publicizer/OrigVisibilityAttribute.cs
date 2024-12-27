// Taken from https://github.com/psyGamer/BepInEx.AssemblyPublicizer/blob/master/BepInEx.AssemblyPublicizer/OriginalAttributesAttribute.cs

using System.Collections.Generic;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace CelesteMod.Publicizer;

internal class OrigVisibilityAttribute {
    private enum PublicizeTarget {
        Types, Methods, Fields
    }
    
    private static Dictionary<PublicizeTarget, string> _typeNames = new() {
        [PublicizeTarget.Types] = "TypeAttributes",
        [PublicizeTarget.Methods] = "MethodAttributes",
        [PublicizeTarget.Fields] = "FieldAttributes",
    };

    private Dictionary<PublicizeTarget, TypeSignature> _attributesTypes = new();
    private Dictionary<PublicizeTarget, MethodDefinition> _constructors = new();

    public TypeDefinition Type { get; }

    public OrigVisibilityAttribute(ModuleDefinition module) {
        var corLibScope = module.CorLibTypeFactory.CorLibScope;
        var attributeReference = corLibScope.CreateTypeReference("System", "Attribute").ImportWith(module.DefaultImporter);
        var baseConstructorReference = attributeReference.CreateMemberReference(".ctor", MethodSignature.CreateInstance(module.CorLibTypeFactory.Void)).ImportWith(module.DefaultImporter);

        Type = new TypeDefinition(
            "CelesteMod.Publicizer", nameof(OrigVisibilityAttribute),
            TypeAttributes.NotPublic | TypeAttributes.Sealed,
            attributeReference
        );
        module.TopLevelTypes.Add(Type);

        foreach (var pair in _typeNames) {
            var attributesType = _attributesTypes[pair.Key] = corLibScope.CreateTypeReference("System.Reflection", pair.Value).ImportWith(module.DefaultImporter).ToTypeSignature();

            var constructorDefinition = new MethodDefinition(".ctor",
                MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName | MethodAttributes.Public,
                MethodSignature.CreateInstance(module.CorLibTypeFactory.Void, attributesType)
            );
            Type.Methods.Add(constructorDefinition);

            var body = constructorDefinition.CilMethodBody = new CilMethodBody(constructorDefinition);
            body.Instructions.Add(CilOpCodes.Ldarg_0);
            body.Instructions.Add(CilOpCodes.Call, baseConstructorReference);
            body.Instructions.Add(CilOpCodes.Ret);

            _constructors[pair.Key] = constructorDefinition;
        }
    }

    private CustomAttribute ToCustomAttribute(PublicizeTarget target, int value) {
        return new CustomAttribute(
            _constructors[target],
            new CustomAttributeSignature(new[] { new CustomAttributeArgument(_attributesTypes[target], value) })
        );
    }

    public CustomAttribute ToCustomAttribute(TypeAttributes attributes) => ToCustomAttribute(PublicizeTarget.Types, (int)attributes);
    public CustomAttribute ToCustomAttribute(MethodAttributes attributes) => ToCustomAttribute(PublicizeTarget.Methods, (int)attributes);
    public CustomAttribute ToCustomAttribute(FieldAttributes attributes) => ToCustomAttribute(PublicizeTarget.Fields, (int)attributes);
}
