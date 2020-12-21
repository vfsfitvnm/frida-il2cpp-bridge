import { il2CppLibraryName } from "../utils/platform";
import { lazy } from "../utils/decorators";
import { create, resolve } from "../utils/api-factory";

/** @internal */
export default class Api {
    @lazy
    static get _library() {
        return Process.getModuleByName(il2CppLibraryName!);
    }

    @lazy
    static get _arrayGetElements() {
        return create("pointer", "il2cpp_array_elements", "pointer");
    }

    @lazy
    static get _arrayGetLength() {
        return create("uint32", "il2cpp_array_length", "pointer");
    }

    @lazy
    static get _arrayNew() {
        return create("pointer", "il2cpp_array_new", "pointer", "uint32");
    }

    @lazy
    static get _assemblyGetImage() {
        return create("pointer", "il2cpp_assembly_get_image", "pointer");
    }

    @lazy
    static get _assemblyGetName() {
        return create("utf8string", "il2cpp_assembly_get_name", "pointer");
    }

    @lazy
    static get _classFromName() {
        return create("pointer", "il2cpp_class_from_name", "pointer", "utf8string", "utf8string");
    }

    @lazy
    static get _classFromType() {
        return create("pointer", "il2cpp_class_from_type", "pointer");
    }

    @lazy
    static get _classGetArrayClass() {
        return create("pointer", "il2cpp_array_class_get", "pointer", "uint32");
    }

    @lazy
    static get _classGetArrayElementSize() {
        return create("int", "il2cpp_class_array_element_size", "pointer");
    }

    @lazy
    static get _classGetAssemblyName() {
        return create("utf8string", "il2cpp_class_get_assemblyname", "pointer");
    }

    @lazy
    static get _classGetDeclaringType() {
        return create("pointer", "il2cpp_class_get_declaring_type", "pointer");
    }

    @lazy
    static get _classGetElementClass() {
        return create("pointer", "il2cpp_class_get_element_class", "pointer");
    }

    @lazy
    static get _classGetFieldCount() {
        return create("uint16", "il2cpp_class_get_field_count", "pointer");
    }

    @lazy
    static get _classGetFields() {
        return create("pointer", "il2cpp_class_get_fields", "pointer", "pointer");
    }

    @lazy
    static get _classGetImage() {
        return create("pointer", "il2cpp_class_get_image", "pointer");
    }

    @lazy
    static get _classGetInstanceSize() {
        return create("uint32", "il2cpp_class_instance_size", "pointer");
    }

    @lazy
    static get _classGetInterfaceCount() {
        return create("uint16", "il2cpp_class_get_interface_count", "pointer");
    }

    @lazy
    static get _classGetInterfaces() {
        return create("pointer", "il2cpp_class_get_interfaces", "pointer", "pointer");
    }

    @lazy
    static get _classGetMethodCount() {
        return create("uint16", "il2cpp_class_get_method_count", "pointer");
    }

    @lazy
    static get _classGetMethods() {
        return create("pointer", "il2cpp_class_get_methods", "pointer", "pointer");
    }

    @lazy
    static get _classGetName() {
        return create("utf8string", "il2cpp_class_get_name", "pointer");
    }

    @lazy
    static get _classGetNamespace() {
        return create("utf8string", "il2cpp_class_get_namespace", "pointer");
    }

    @lazy
    static get _classGetParent() {
        return create("pointer", "il2cpp_class_get_parent", "pointer");
    }

    @lazy
    static get _classGetStaticFieldData() {
        return create("pointer", "il2cpp_class_get_static_field_data", "pointer");
    }

    @lazy
    static get _classGetType() {
        return create("pointer", "il2cpp_class_get_type", "pointer");
    }

    @lazy
    static get _classHasStaticConstructor() {
        return create("bool", "il2cpp_class_has_static_constructor", "pointer");
    }

    @lazy
    static get _classInit() {
        return create("void", "il2cpp_runtime_class_init", "pointer");
    }

    @lazy
    static get _classIsEnum() {
        return create("bool", "il2cpp_class_is_enum", "pointer");
    }

    @lazy
    static get _classIsInterface() {
        return create("bool", "il2cpp_class_is_interface", "pointer");
    }

    @lazy
    static get _classIsStaticConstructorFinished() {
        return create("bool", "il2cpp_class_is_static_constructor_finished", "pointer");
    }

    @lazy
    static get _classIsStruct() {
        return create("bool", "il2cpp_class_is_valuetype", "pointer");
    }

    @lazy
    static get _domainGet() {
        return create("pointer", "il2cpp_domain_get");
    }

    @lazy
    static get _domainGetAssemblies() {
        return create("pointer", "il2cpp_domain_get_assemblies", "pointer", "pointer");
    }

    @lazy
    static get _domainGetName() {
        return create("utf8string", "il2cpp_domain_get_name", "pointer");
    }

    @lazy
    static get _fieldGetClass() {
        return create("pointer", "il2cpp_field_get_parent", "pointer");
    }

    @lazy
    static get _fieldGetName() {
        return create("utf8string", "il2cpp_field_get_name", "pointer");
    }

    @lazy
    static get _fieldGetOffset() {
        return create("int32", "il2cpp_field_get_offset", "pointer");
    }

    @lazy
    static get _fieldGetStaticValue() {
        return create("void", "il2cpp_field_static_get_value", "pointer", "pointer");
    }

    @lazy
    static get _fieldGetStaticValue2() {
        return create("void", "il2cpp_field_static_get_value", "pointer", "pointer");
    }

    @lazy
    static get _fieldGetType() {
        return create("pointer", "il2cpp_field_get_type", "pointer");
    }

    @lazy
    static get _fieldIsInstance() {
        return create("bool", "il2cpp_field_is_instance", "pointer");
    }

    @lazy
    static get _fieldIsLiteral() {
        return create("bool", "il2cpp_field_is_literal", "pointer");
    }

    @lazy
    static get _gcCollect() {
        return create("void", "il2cpp_gc_collect", "int");
    }

    @lazy
    static get _gcCollectALittle() {
        return create("void", "il2cpp_gc_collect_a_little");
    }

    @lazy
    static get _gcDisable() {
        return create("void", "il2cpp_gc_disable");
    }

    @lazy
    static get _gcEnable() {
        return create("void", "il2cpp_gc_enable");
    }

    @lazy
    static get _gcIsDisabled() {
        return create("bool", "il2cpp_gc_is_disabled");
    }

    @lazy
    static get _genericClassGetCachedClass() {
        return create("pointer", "il2cpp_field_is_literal", "pointer");
    }

    @lazy
    static get _imageGetClass() {
        return create("pointer", "il2cpp_image_get_class", "pointer", "uint");
    }

    @lazy
    static get _imageGetClassCount() {
        return create("uint32", "il2cpp_image_get_class_count", "pointer");
    }

    @lazy
    static get _imageGetClassStart() {
        return create("uint32", "il2cpp_image_get_class_start", "pointer");
    }

    @lazy
    static get _imageGetName() {
        return create("utf8string", "il2cpp_image_get_name", "pointer");
    }

    @lazy
    static get _init() {
        return resolve("il2cpp_init");
    }

    @lazy
    static get _livenessCalculationBegin() {
        return create("pointer", "il2cpp_unity_liveness_calculation_begin", "pointer", "int", "pointer", "pointer", "pointer", "pointer");
    }

    @lazy
    static get _livenessCalculationEnd() {
        return create("void", "il2cpp_unity_liveness_calculation_end", "pointer");
    }

    @lazy
    static get _livenessCalculationFromStatics() {
        return create("void", "il2cpp_unity_liveness_calculation_from_statics", "pointer");
    }

    @lazy
    static get _memorySnapshotCapture() {
        return create("pointer", "il2cpp_capture_memory_snapshot");
    }

    @lazy
    static get _memorySnapshotFree() {
        return create("void", "il2cpp_free_captured_memory_snapshot", "pointer");
    }

    @lazy
    static get _memorySnapshotGetTrackedObjectCount() {
        return create("uint64", "il2cpp_memory_snapshot_get_tracked_object_count", "pointer");
    }

    @lazy
    static get _memorySnapshotGetObjects() {
        return create("pointer", "il2cpp_memory_snapshot_get_objects", "pointer");
    }

    @lazy
    static get _methodGetClass() {
        return create("pointer", "il2cpp_method_get_class", "pointer");
    }

    @lazy
    static get _methodGetName() {
        return create("utf8string", "il2cpp_method_get_name", "pointer");
    }

    @lazy
    static get _methodGetParamCount() {
        return create("uint8", "il2cpp_method_get_param_count", "pointer");
    }

    @lazy
    static get _methodGetParameters() {
        return create("pointer", "il2cpp_method_get_parameters", "pointer", "pointer");
    }

    @lazy
    static get _methodGetPointer() {
        return create("pointer", "il2cpp_method_get_pointer", "pointer");
    }

    @lazy
    static get _methodGetReturnType() {
        return create("pointer", "il2cpp_method_get_return_type", "pointer");
    }

    @lazy
    static get _methodIsGeneric() {
        return create("bool", "il2cpp_method_is_generic", "pointer");
    }

    @lazy
    static get _methodIsInflated() {
        return create("bool", "il2cpp_method_is_inflated", "pointer");
    }

    @lazy
    static get _methodIsInstance() {
        return create("bool", "il2cpp_method_is_instance", "pointer");
    }

    @lazy
    static get _objectGetClass() {
        return create("pointer", "il2cpp_object_get_class", "pointer");
    }

    @lazy
    static get _objectGetHeaderSize() {
        return create("uint", "il2cpp_object_header_size");
    }

    @lazy
    static get _objectNew() {
        return create("pointer", "il2cpp_object_new", "pointer");
    }

    @lazy
    static get _objectUnbox() {
        return create("pointer", "il2cpp_object_unbox", "pointer");
    }

    @lazy
    static get _parameterGetName() {
        return create("utf8string", "il2cpp_parameter_get_name", "pointer");
    }

    @lazy
    static get _parameterGetPosition() {
        return create("int32", "il2cpp_parameter_get_position", "pointer");
    }

    @lazy
    static get _parameterGetType() {
        return create("pointer", "il2cpp_parameter_get_type", "pointer");
    }

    @lazy
    static get _stringChars() {
        return create("pointer", "il2cpp_string_chars", "pointer");
    }

    @lazy
    static get _stringLength() {
        return create("int32", "il2cpp_string_length", "pointer");
    }

    @lazy
    static get _stringNew() {
        return create("pointer", "il2cpp_string_new", "utf8string");
    }

    @lazy
    static get _stringSetLength() {
        return create("void", "il2cpp_string_set_length", "pointer", "int32");
    }

    @lazy
    static get _valueBox() {
        return create("pointer", "il2cpp_value_box", "pointer", "pointer");
    }

    @lazy
    static get _threadAttach() {
        return create("void", "il2cpp_thread_attach", "pointer");
    }

    @lazy
    static get _typeGetClassOrElementClass() {
        return create("pointer", "il2cpp_type_get_class_or_element_class", "pointer");
    }

    @lazy
    static get _typeGetDataType() {
        return create("pointer", "il2cpp_type_get_data_type", "pointer");
    }

    @lazy
    static get _typeGetGenericClass() {
        return create("pointer", "il2cpp_type_get_generic_class", "pointer");
    }

    @lazy
    static get _typeGetName() {
        return create("utf8string", "il2cpp_type_get_name", "pointer");
    }

    @lazy
    static get _typeGetTypeEnum() {
        return create("int", "il2cpp_type_get_type", "pointer");
    }

    @lazy
    static get _typeIsByReference() {
        return create("bool", "il2cpp_type_is_byref", "pointer");
    }

    @lazy
    static get _typeOffsetOfTypeEnum() {
        return create("uint16", "il2cpp_type_offset_of_type");
    }
}
