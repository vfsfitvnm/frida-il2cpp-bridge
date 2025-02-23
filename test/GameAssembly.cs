using System;

class Class : Interface
{
    static int sfield;

    int field;

    static Enum enumfield;

    static Class()
    {
        Class.enumfield = Enum.Second;
    }

    unsafe void Method(bool* pointer, ref bool reference, bool[] array)
    {
        Class.sfield++;
        this.field++;
    }

    static void StaticGenericMethod<T, U>(T t, U u)
    {

    }

    class InnerClass
    {
        class InnerInnerClass
        {

        }
    }
}

class ParentClass {
}

class ChildClass : ParentClass {
}

class ChildChildClass : ChildClass {
}

class AnotherChildClass : ParentClass {
}

class AnotherChildChildClass : ParentClass {
}

class OverloadTest {
    int Method(ParentClass instance) {
        return 0;
    }

    int Method(ChildClass instance) {
        return 1;
    }

    int Method(AnotherChildChildClass instance) {
        return 2;
    }

    int Method2(ParentClass a, ChildClass b) {
        return 0;
    }

    int Method2(ChildClass a, ParentClass b) {
        return 1;
    }

    int AnotherMethod() {
        return 0;
    }

    int AnotherMethod(int value) {
        return value;
    }
}

class OverloadTest2 : OverloadTest {
    int Method(AnotherChildClass instance) {
        return 3;
    }

    int AnotherMethod() {
        return 2;
    }
}

abstract class AbstractGenericClass<T, U>
{

}

class PartiallyInflatedClass<T> : AbstractGenericClass<T, String>
{

}

class InflatedClass : AbstractGenericClass<String, String>
{

}

struct Struct
{

}

struct EmptyStruct
{

}

enum Enum
{
    First,
    Second,
    Third
}

enum LongEnum : ulong
{
    First,
    Second,
    Third
}

enum EmptyEnum
{

}


interface Interface
{

}