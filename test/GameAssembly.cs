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

public class Il2CppObjectTest
{
    public static int F;

    public static int A(int a)
    {
        return 0;
    }

    public int A (string a)
    {
        return 1;
    }

    public static int B()
    {
        return 2;
    }

    public static int C(int a)
    {
        return 3;
    }

    public int C()
    {
        return 4;
    }
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

namespace MethodInflateTest {
    class Parent<ClassType> {
        static int A<T>() {
            return 0;
        }

        static int A<T, U>() {
            return 1;
        }

        static int B() {
            return 0;
        }

        static int B<T>(T a) {
            return 1;
        }

        static int B<T, U>() {
            return 2;
        }

        static int C(ClassType a) {
            return 0;
        }

        static int C<T>(T a) {
            return 1;
        }

        static int C<T>(String a) {
            return 2;
        }
        
        static int D(ClassType a) {
            return 0;
        }
    }

    class Child : Parent<System.Object> {
        static int A<T, U, V>() {
            return 3;
        }
    }
}
