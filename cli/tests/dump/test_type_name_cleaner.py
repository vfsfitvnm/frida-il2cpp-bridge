import unittest

from src.dump.dumper import TypeNameCleaner


class TestTypeNameCleaner(unittest.TestCase):
    def test_add_ref_keyword_for_reference_types(self):
        for type_name, expected in [
            ("", None),
            ("&", "ref "),
            ("System.Boolean&", "ref System.Boolean"),
            ("<Module>&", "ref <Module>"),
            ("<>__message&", "ref <>__message"),
            ("Unicode.Contraction[]&", "ref Unicode.Contraction[]"),
            ("System.Byte*&", "ref System.Byte*"),
            ("System.ArraySegment<T>&", "ref System.ArraySegment<T>"),
            ("System.ArraySegment<&T>", None),
            ("Something<T&>", None),
            ("&Something", None),
        ]:
            self.assertEqual(
                TypeNameCleaner.add_ref_keyword_for_reference_types(type_name),
                expected if expected is not None else type_name,
            )

    def test_add_space_after_comma_in_generic_parameters(self):
        for type_name, expected in [
            ("", None),
            (",", None),
            (", ", None),
            ("System.Boolean,", "System.Boolean,"),
            ("<Module,>", "<Module, >"),
            ("System.Action<T,U>", "System.Action<T, U>"),
            ("System.Action<T, U>", None),
            (
                "Action<T,Action<T,Action<T,U,J>>,K>",
                "Action<T, Action<T, Action<T, U, J>>, K>",
            ),
            ("<>Foo<A>", None),
            ("<>Foo<A,B>", "<>Foo<A, B>"),
        ]:
            self.assertEqual(
                TypeNameCleaner.add_space_after_comma_in_generic_parameters(type_name),
                expected if expected is not None else type_name,
            )

    def test_replace_known_types(self):
        mapping = {
            "System.Boolean": "bool",
        }
        for type_name, expected in [
            ("", None),
            ("System.Boolean", "bool"),
            ("System.Boolean&", "bool&"),
            ("System.Boolean*", "bool*"),
            ("System.Boolean**", "bool**"),
            ("System.Boolean.Something", None),
            ("System.Action<System.Boolean>", "System.Action<bool>"),
            ("System.Action<System.Boolean.A>", None),
            ("System.Foo<System.Boolean,System.Boolean>", "System.Foo<bool,bool>"),
            ("System.Foo<System.Boolean, System.Boolean>", "System.Foo<bool, bool>"),
            (
                "Foo<Bar<System.Boolean>, Foo<System.Boolean>>",
                "Foo<Bar<bool>, Foo<bool>>",
            ),
            ("Foo<System.Boolean**>", "Foo<bool**>"),
            ("Foo<System.Boolean&>", "Foo<System.Boolean&>"),
        ]:
            self.assertEqual(
                TypeNameCleaner.replace_known_types(type_name, mapping),
                expected if expected is not None else type_name,
            )
